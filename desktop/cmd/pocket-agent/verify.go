package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
)

// Google's current Android hardware attestation roots, fetched from
// https://android.googleapis.com/attestation/root. Google rotates these on the
// order of once every several years; if a chain rooted at an unknown CA appears,
// re-fetch and rebuild rather than relaxing the check.
//
//go:embed google_attestation_roots.pem
var googleAttestationRootsPEM []byte

// The container format ssh-keygen writes with -O write-attestation=<file>.
// See OpenSSH ssh-keygen.c do_download_sk → do_write_attestation:
//
//	string  "ssh-sk-attest-v01"
//	string  attestation_cert   (DER X.509)
//	string  enrollment_sig     (SK signature over the challenge — unused here)
//	string  authdata           (we pack intermediate certs in here)
//	uint32  0                  (reserved flags)
//	string  ""                 (reserved)
//
// where each "string" is [uint32 BE length][bytes].
const sshAttestMagic = "ssh-sk-attest-v01"

// Android Keystore attestation extension. The value is a SEQUENCE
// (KeyDescription) carrying the attestation challenge and security level.
// https://source.android.com/docs/security/features/keystore/attestation
var keyDescriptionOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}

func cmdVerifyAttestation(args []string) {
	fs := flag.NewFlagSet("verify-attestation", flag.ExitOnError)
	expectChallenge := fs.String("challenge", "", "Expected attestation challenge (hex). If set, fails on mismatch.")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, `Usage: pocket-agent verify-attestation [--challenge HEX] <file>

Parses an attestation file written by ssh-keygen -O write-attestation=<file>,
verifies the certificate chain produced by PocketKey, and prints the Android
Keystore Key Description (security level, challenge, etc.).

A successful run on a Play-certified device proves the SSH key actually lives
in StrongBox or the TEE on the phone — not in unprotected app storage.`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(2)
	}

	data, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		log.Fatalf("read %s: %v", fs.Arg(0), err)
	}

	leafDER, authdata, err := parseSshAttestation(data)
	if err != nil {
		log.Fatalf("parse attestation file: %v", err)
	}
	intermediates, err := parsePackedIntermediates(authdata)
	if err != nil {
		log.Fatalf("parse intermediates: %v", err)
	}

	allDER := append([][]byte{leafDER}, intermediates...)
	certs := make([]*x509.Certificate, len(allDER))
	for i, der := range allDER {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			log.Fatalf("parse cert %d: %v", i, err)
		}
		certs[i] = c
	}

	fmt.Printf("Attestation chain (%d certs):\n", len(certs))
	for i, c := range certs {
		fmt.Printf("  [%d] subject: %s\n", i, c.Subject)
		fmt.Printf("      issuer:  %s\n", c.Issuer)
	}

	// Verify signature linkage from leaf up to the (self-signed) root.
	linkageOK := true
	for i := 0; i < len(certs)-1; i++ {
		if err := certs[i].CheckSignatureFrom(certs[i+1]); err != nil {
			fmt.Printf("  ✗ cert[%d] signature NOT verified by cert[%d]: %v\n", i, i+1, err)
			linkageOK = false
		}
	}
	if linkageOK && len(certs) > 1 {
		fmt.Println("Chain signature linkage: OK")
	} else if len(certs) == 1 {
		fmt.Println("Chain signature linkage: N/A (only leaf — no attestation chain)")
	}

	// Anchor: the terminal cert in the chain must match one of Google's published
	// hardware attestation roots. Without this check the "attestation" is just a
	// self-signed claim by whoever built the chain.
	rootCAs, err := loadGoogleAttestationRoots()
	if err != nil {
		log.Fatalf("load embedded Google roots: %v", err)
	}
	terminal := certs[len(certs)-1]
	if !rootIsPinned(terminal, rootCAs) {
		fmt.Println()
		fmt.Printf("✗ Chain does NOT terminate at a known Google hardware attestation root.\n")
		fmt.Printf("  Terminal cert subject: %s\n", terminal.Subject)
		fmt.Printf("  Terminal cert SHA-256: %x\n", certFingerprint(terminal))
		fmt.Printf("\nThis attestation is not trustworthy — the chain could have been forged by\n")
		fmt.Printf("anyone. If you believe this is a legitimate rotation, refetch the roots from\n")
		fmt.Printf("https://android.googleapis.com/attestation/root and rebuild pocket-agent.\n")
		os.Exit(1)
	}
	fmt.Println("Chain anchors to Google hardware attestation root: OK")

	// Find the Key Description extension on the leaf.
	var kdExt []byte
	for _, e := range certs[0].Extensions {
		if e.Id.Equal(keyDescriptionOID) {
			kdExt = e.Value
			break
		}
	}
	if kdExt == nil {
		fmt.Println()
		log.Fatal("Leaf cert has no Android Key Description extension (OID 1.3.6.1.4.1.11129.2.1.17).\n" +
			"This means the key was not generated with an attestation challenge, or the device\n" +
			"does not support hardware attestation. Re-enroll with ssh-keygen -t ecdsa-sk on a\n" +
			"Play-certified device.")
	}

	// Decode the leading fields of KeyDescription. The trailing AuthorizationLists
	// are intentionally left as RawValue — we don't need to walk every authorization
	// to prove hardware backing, and parsing them fully requires modelling all the
	// context-tagged optional fields.
	var kd struct {
		AttestationVersion       int
		AttestationSecurityLevel asn1.Enumerated
		KeyMintVersion           int
		KeyMintSecurityLevel     asn1.Enumerated
		AttestationChallenge     []byte
		UniqueID                 []byte
		SoftwareEnforced         asn1.RawValue
		HardwareEnforced         asn1.RawValue
	}
	if _, err := asn1.Unmarshal(kdExt, &kd); err != nil {
		log.Fatalf("parse KeyDescription: %v", err)
	}

	fmt.Println()
	fmt.Println("Key Description:")
	fmt.Printf("  Attestation version:        %d\n", kd.AttestationVersion)
	fmt.Printf("  Attestation security level: %s\n", securityLevelName(int(kd.AttestationSecurityLevel)))
	fmt.Printf("  KeyMint version:            %d\n", kd.KeyMintVersion)
	fmt.Printf("  KeyMint security level:     %s\n", securityLevelName(int(kd.KeyMintSecurityLevel)))
	fmt.Printf("  Attestation challenge:      %s\n", hex.EncodeToString(kd.AttestationChallenge))

	switch int(kd.KeyMintSecurityLevel) {
	case 1:
		fmt.Println("\n→ Key is hardware-backed (TrustedEnvironment).")
	case 2:
		fmt.Println("\n→ Key is hardware-backed in StrongBox (highest assurance).")
	default:
		fmt.Println("\n⚠ Key is NOT hardware-backed — it lives in software, not in TEE/StrongBox.")
	}

	if *expectChallenge != "" {
		want, err := hex.DecodeString(*expectChallenge)
		if err != nil {
			log.Fatalf("bad --challenge hex: %v", err)
		}
		if !bytes.Equal(want, kd.AttestationChallenge) {
			fmt.Printf("\n✗ Challenge MISMATCH: expected %s\n", hex.EncodeToString(want))
			os.Exit(1)
		}
		fmt.Println("\n✓ Challenge matches expected value.")
	}
}

// loadGoogleAttestationRoots parses the embedded PEM bundle once. Returns an
// error only if the bundle is empty or unparseable, which would be a build bug.
func loadGoogleAttestationRoots() ([]*x509.Certificate, error) {
	var roots []*x509.Certificate
	rest := googleAttestationRootsPEM
	for {
		block, next := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = next
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse embedded root: %w", err)
		}
		roots = append(roots, c)
	}
	if len(roots) == 0 {
		return nil, errors.New("no roots in embedded bundle")
	}
	return roots, nil
}

// rootIsPinned reports whether c matches one of the trusted roots by DER bytes.
// Comparing full DER is stricter than comparing public keys: it pins both the
// key and the rest of the cert (subject, validity, extensions).
func rootIsPinned(c *x509.Certificate, roots []*x509.Certificate) bool {
	for _, r := range roots {
		if bytes.Equal(c.Raw, r.Raw) {
			return true
		}
	}
	return false
}

func certFingerprint(c *x509.Certificate) []byte {
	h := sha256.Sum256(c.Raw)
	return h[:]
}

func securityLevelName(n int) string {
	switch n {
	case 0:
		return "Software"
	case 1:
		return "TrustedEnvironment"
	case 2:
		return "StrongBox"
	default:
		return fmt.Sprintf("Unknown(%d)", n)
	}
}

// parseSshAttestation parses the ssh-sk-attest-v01 container.
func parseSshAttestation(data []byte) (attCert, authdata []byte, err error) {
	r := &sshbufReader{data: data}
	magic, err := r.readString()
	if err != nil {
		return nil, nil, fmt.Errorf("read magic: %w", err)
	}
	if string(magic) != sshAttestMagic {
		return nil, nil, fmt.Errorf("unexpected magic: %q (want %q)", string(magic), sshAttestMagic)
	}
	if attCert, err = r.readString(); err != nil {
		return nil, nil, fmt.Errorf("read attestation_cert: %w", err)
	}
	if _, err = r.readString(); err != nil { // enrollment_sig (unused for Android attestation)
		return nil, nil, fmt.Errorf("read enrollment_sig: %w", err)
	}
	if authdata, err = r.readString(); err != nil {
		return nil, nil, fmt.Errorf("read authdata: %w", err)
	}
	if len(attCert) == 0 {
		return nil, nil, errors.New("attestation_cert is empty (key may have been enrolled without a challenge)")
	}
	return attCert, authdata, nil
}

// parsePackedIntermediates parses the [count:1] {[len_be:2][cert:N]}* format
// the SK bridge writes into authdata. Returns nil for empty input.
func parsePackedIntermediates(buf []byte) ([][]byte, error) {
	if len(buf) == 0 {
		return nil, nil
	}
	count := int(buf[0])
	out := make([][]byte, 0, count)
	off := 1
	for i := 0; i < count; i++ {
		if len(buf) < off+2 {
			return nil, fmt.Errorf("truncated at cert %d length", i)
		}
		l := int(binary.BigEndian.Uint16(buf[off:]))
		off += 2
		if len(buf) < off+l {
			return nil, fmt.Errorf("truncated at cert %d body", i)
		}
		cert := make([]byte, l)
		copy(cert, buf[off:off+l])
		out = append(out, cert)
		off += l
	}
	return out, nil
}

type sshbufReader struct {
	data []byte
	off  int
}

func (r *sshbufReader) readString() ([]byte, error) {
	if len(r.data) < r.off+4 {
		return nil, errors.New("short read on length")
	}
	n := int(binary.BigEndian.Uint32(r.data[r.off:]))
	r.off += 4
	if len(r.data)-r.off < n {
		return nil, errors.New("short read on body")
	}
	out := r.data[r.off : r.off+n]
	r.off += n
	return out, nil
}
