package pairing

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/skip2/go-qrcode"
)

// PairingVersion is the current pairing payload version.
const PairingVersion = 2

// PairingTTL is how long a generated QR code remains valid.
const PairingTTL = 5 * time.Minute

// signatureDomain is the domain-separation prefix bound into the pairing
// signature transcript. Changing it breaks compatibility with older clients
// and is intentional whenever the transcript layout changes.
const signatureDomain = "pocket-pair-v2\x00"

// PairingPayload is the JSON structure encoded in the QR code.
//
// The signature is computed over a domain-separated transcript:
//
//	signatureDomain || uint64(issuedAtMs) || uint64(expiresAtMs)
//	  || nonce || x509PubKey || utf8(label)
//
// This binds the signature to the validity window, the device key, and the
// label — preventing reuse of an older signature with edited fields.
type PairingPayload struct {
	Version      int    `json:"version"`
	PublicKey    string `json:"publicKey"`    // Base64 X.509 encoded Ed25519 public key
	Nonce        string `json:"nonce"`        // Base64 random 32 bytes
	Label        string `json:"label"`
	IssuedAtMs   int64  `json:"issuedAtMs"`   // Unix epoch milliseconds when QR was generated
	ExpiresAtMs  int64  `json:"expiresAtMs"`  // Unix epoch milliseconds when QR stops being valid
	Signature    string `json:"signature"`    // Base64 Ed25519 signature over the transcript above
}

// SignatureTranscript builds the byte sequence that the pairing signature
// covers. Exported so the verifier (Android) and any tests can rebuild it
// identically.
func SignatureTranscript(issuedAtMs, expiresAtMs int64, nonce, x509PubKey []byte, label string) []byte {
	var buf []byte
	buf = append(buf, []byte(signatureDomain)...)
	var times [16]byte
	binary.BigEndian.PutUint64(times[0:8], uint64(issuedAtMs))
	binary.BigEndian.PutUint64(times[8:16], uint64(expiresAtMs))
	buf = append(buf, times[:]...)
	buf = append(buf, nonce...)
	buf = append(buf, x509PubKey...)
	buf = append(buf, []byte(label)...)
	return buf
}

// DeviceKeys holds the proxy's Ed25519 keypair.
type DeviceKeys struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
}

// Config holds pairing configuration.
type Config struct {
	KeysDir string
	Label   string
}

// LoadOrGenerateKeys loads existing keys or generates new ones.
func LoadOrGenerateKeys(keysDir string) (*DeviceKeys, error) {
	if err := os.MkdirAll(keysDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create keys dir: %w", err)
	}

	privPath := filepath.Join(keysDir, "device.key")
	pubPath := filepath.Join(keysDir, "device.pub")

	// Try loading existing keys
	privBytes, err := os.ReadFile(privPath)
	if err == nil {
		privKey := ed25519.PrivateKey(privBytes)
		pubKey := privKey.Public().(ed25519.PublicKey)
		log.Println("Loaded existing device keypair")
		return &DeviceKeys{PrivateKey: privKey, PublicKey: pubKey}, nil
	}

	// Generate new keypair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate keypair: %w", err)
	}

	if err := os.WriteFile(privPath, privKey, 0600); err != nil {
		return nil, fmt.Errorf("failed to save private key: %w", err)
	}
	if err := os.WriteFile(pubPath, pubKey, 0644); err != nil {
		return nil, fmt.Errorf("failed to save public key: %w", err)
	}

	log.Println("Generated new device keypair")
	return &DeviceKeys{PrivateKey: privKey, PublicKey: pubKey}, nil
}

// GenerateQR creates a pairing QR code and saves it as a PNG file.
// Also prints the QR to the terminal.
func GenerateQR(keys *DeviceKeys, label string, outputPath string) error {
	// Generate random nonce
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encode public key in X.509/PKIX format
	x509PubKey, err := x509.MarshalPKIXPublicKey(keys.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}

	now := time.Now()
	issuedAtMs := now.UnixMilli()
	expiresAtMs := now.Add(PairingTTL).UnixMilli()

	transcript := SignatureTranscript(issuedAtMs, expiresAtMs, nonce, x509PubKey, label)
	signature := ed25519.Sign(keys.PrivateKey, transcript)

	payload := PairingPayload{
		Version:     PairingVersion,
		PublicKey:   base64.RawStdEncoding.EncodeToString(x509PubKey),
		Nonce:       base64.RawStdEncoding.EncodeToString(nonce),
		Label:       label,
		IssuedAtMs:  issuedAtMs,
		ExpiresAtMs: expiresAtMs,
		Signature:   base64.RawStdEncoding.EncodeToString(signature),
	}

	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Generate QR code
	qr, err := qrcode.New(string(jsonBytes), qrcode.Medium)
	if err != nil {
		return fmt.Errorf("failed to generate QR code: %w", err)
	}

	// Print to terminal
	fmt.Println("\n=== Scan this QR code with PocketSSHAgent app ===")
	fmt.Println(qr.ToSmallString(false))

	// Save as PNG
	if outputPath != "" {
		if err := qr.WriteFile(256, outputPath); err != nil {
			return fmt.Errorf("failed to write QR PNG: %w", err)
		}
		log.Printf("QR code saved to: %s", outputPath)
	}

	return nil
}
