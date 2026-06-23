package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
	"os/exec"
	"regexp"
	"time"
)

const (
	msgSKEnrollRequest  byte = 103
	msgSKEnrollResponse byte = 104
	msgSKSignRequest    byte = 105
	msgSKSignResponse          byte = 106
	msgSKLoadResidentRequest   byte = 107
	msgSKLoadResidentResponse  byte = 108
	msgFailure                 byte = 5

	agentURI       = "content://com.example.pocketsshagent.agent"
	signTimeout    = 90 * time.Second
	defaultTimeout = 15 * time.Second
	pollInterval   = 250 * time.Millisecond
)

// ContentBackend talks to the Android app's AgentContentProvider via the
// `content call` CLI. A request is initiated (the app authorizes the caller by
// UID), and the encrypted result is then polled until ready. Decoupling
// initiate from poll means a biometric prompt can take as long as the user
// needs without holding a binder transaction open.
type ContentBackend struct{}

var globalBackend = &ContentBackend{}

func getBackend() *ContentBackend {
	return globalBackend
}

func (b *ContentBackend) SendMessage(msg []byte, timeout time.Duration) ([]byte, error) {
	deadline := time.Now().Add(timeout)

	// 1) initiate: hand over the request, receive a requestId + per-request AES key.
	initOut, err := b.contentCall(defaultTimeout, "initiate", base64.StdEncoding.EncodeToString(msg))
	if err != nil {
		return nil, fmt.Errorf("initiate: %w", err)
	}
	if e := bundleString(initOut, "e"); e != "" {
		return nil, fmt.Errorf("initiate rejected: %s", e)
	}
	requestID := bundleString(initOut, "id")
	keyB64 := bundleString(initOut, "k")
	if requestID == "" || keyB64 == "" {
		return nil, fmt.Errorf("initiate: missing id/key in response: %q", initOut)
	}
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return nil, fmt.Errorf("initiate: bad key: %w", err)
	}

	// 2) poll until the (possibly biometric-gated) result is ready.
	for {
		pollOut, err := b.contentCall(defaultTimeout, "poll", requestID)
		if err != nil {
			return nil, fmt.Errorf("poll: %w", err)
		}
		switch bundleString(pollOut, "s") {
		case "done":
			enc, err := base64.StdEncoding.DecodeString(bundleString(pollOut, "d"))
			if err != nil {
				return nil, fmt.Errorf("poll: bad result data: %w", err)
			}
			framed, err := decryptResponse(key, enc)
			if err != nil {
				return nil, err
			}
			if len(framed) < 4 {
				return nil, fmt.Errorf("response too short (%d bytes)", len(framed))
			}
			return framed[4:], nil
		case "pending":
			if time.Now().After(deadline) {
				return nil, fmt.Errorf("timed out waiting for approval")
			}
			time.Sleep(pollInterval)
		default:
			return nil, fmt.Errorf("poll: unknown request (expired or denied)")
		}
	}
}

func (b *ContentBackend) contentCall(timeout time.Duration, method, arg string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "/system/bin/content", "call",
		"--uri", agentURI,
		"--method", method,
		"--arg", arg)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if s := stderr.String(); s != "" {
		log.Printf("[SK-TERMUX] content call %s stderr: %s", method, s)
	}
	if err != nil {
		return "", fmt.Errorf("content call %s: %w", method, err)
	}
	return string(out), nil
}

// bundleString extracts a key from `content call` output, which prints the
// returned Bundle as: Result: Bundle[{id=..., k=..., ...}]. Values are hex or
// base64 (never contain commas or spaces), so a per-key match is unambiguous.
// The \b anchor prevents "d" from matching inside "id=".
func bundleString(output, key string) string {
	re := regexp.MustCompile(`\b` + regexp.QuoteMeta(key) + `=([A-Za-z0-9+/=_-]+)`)
	m := re.FindStringSubmatch(output)
	if m == nil {
		return ""
	}
	return m[1]
}

// decryptResponse opens an AES-256-GCM blob laid out as [12B nonce][ct][16B tag],
// matching SessionCrypto.seal on the phone.
func decryptResponse(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	ns := gcm.NonceSize()
	if len(data) < ns {
		return nil, fmt.Errorf("ciphertext too short (%d bytes)", len(data))
	}
	pt, err := gcm.Open(nil, data[:ns], data[ns:], nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return pt, nil
}

func (b *ContentBackend) Enroll(application string, alg uint32, flags byte, label string, challenge []byte) (pubkey, keyHandle []byte, actualAlg uint32, attestationChain [][]byte, err error) {
	appHash := sha256.Sum256([]byte(application))
	labelBytes := []byte(label)

	if len(labelBytes) > 0xFFFF {
		return nil, nil, 0, nil, fmt.Errorf("enroll: label too long (%d bytes)", len(labelBytes))
	}
	if len(challenge) > 0xFFFF {
		return nil, nil, 0, nil, fmt.Errorf("enroll: challenge too long (%d bytes)", len(challenge))
	}

	msg := make([]byte, 1+1+32+1+2+len(labelBytes)+2+len(challenge))
	off := 0
	msg[off] = msgSKEnrollRequest
	off++
	msg[off] = byte(alg)
	off++
	copy(msg[off:], appHash[:])
	off += 32
	msg[off] = flags
	off++
	binary.BigEndian.PutUint16(msg[off:], uint16(len(labelBytes)))
	off += 2
	copy(msg[off:], labelBytes)
	off += len(labelBytes)
	binary.BigEndian.PutUint16(msg[off:], uint16(len(challenge)))
	off += 2
	copy(msg[off:], challenge)

	resp, err := b.SendMessage(msg, signTimeout)
	if err != nil {
		return nil, nil, 0, nil, fmt.Errorf("enroll: %w", err)
	}

	if len(resp) < 1 || resp[0] == msgFailure {
		return nil, nil, 0, nil, fmt.Errorf("enroll: rejected by phone")
	}
	if resp[0] != msgSKEnrollResponse {
		return nil, nil, 0, nil, fmt.Errorf("enroll: unexpected response type %d", resp[0])
	}
	if len(resp) < 1+1+2 {
		return nil, nil, 0, nil, fmt.Errorf("enroll: response too short (%d bytes)", len(resp))
	}

	actualAlg = uint32(resp[1])
	pubkeyLen := int(binary.BigEndian.Uint16(resp[2:4]))
	if len(resp) < 4+pubkeyLen+2 {
		return nil, nil, 0, nil, fmt.Errorf("enroll: response truncated at pubkey")
	}
	pubkey = make([]byte, pubkeyLen)
	copy(pubkey, resp[4:4+pubkeyLen])

	rOff := 4 + pubkeyLen
	handleLen := int(binary.BigEndian.Uint16(resp[rOff : rOff+2]))
	rOff += 2
	if len(resp) < rOff+handleLen {
		return nil, nil, 0, nil, fmt.Errorf("enroll: response truncated at handle")
	}
	keyHandle = make([]byte, handleLen)
	copy(keyHandle, resp[rOff:rOff+handleLen])
	rOff += handleLen

	if rOff < len(resp) {
		certCount := int(resp[rOff])
		rOff++
		attestationChain = make([][]byte, 0, certCount)
		for i := 0; i < certCount; i++ {
			if len(resp) < rOff+2 {
				return nil, nil, 0, nil, fmt.Errorf("enroll: response truncated at cert %d length", i)
			}
			certLen := int(binary.BigEndian.Uint16(resp[rOff : rOff+2]))
			rOff += 2
			if len(resp) < rOff+certLen {
				return nil, nil, 0, nil, fmt.Errorf("enroll: response truncated at cert %d body", i)
			}
			cert := make([]byte, certLen)
			copy(cert, resp[rOff:rOff+certLen])
			attestationChain = append(attestationChain, cert)
			rOff += certLen
		}
	}

	log.Printf("[SK-TERMUX] Enroll succeeded: alg=%d handle=%q", actualAlg, string(keyHandle))
	return pubkey, keyHandle, actualAlg, attestationChain, nil
}

func (b *ContentBackend) Sign(alg uint32, application string, keyHandle, data []byte, flags byte) (sigR, sigS []byte, counter uint32, respFlags byte, err error) {
	appHash := sha256.Sum256([]byte(application))
	dataHash := sha256.Sum256(data)

	handleLen := len(keyHandle)
	msg := make([]byte, 1+2+handleLen+32+1+32)
	offset := 0
	msg[offset] = msgSKSignRequest
	offset++
	binary.BigEndian.PutUint16(msg[offset:], uint16(handleLen))
	offset += 2
	copy(msg[offset:], keyHandle)
	offset += handleLen
	copy(msg[offset:], appHash[:])
	offset += 32
	msg[offset] = flags
	offset++
	copy(msg[offset:], dataHash[:])

	log.Println("[SK-TERMUX] Sending sign request (will trigger biometric)...")
	resp, err := b.SendMessage(msg, signTimeout)
	if err != nil {
		return nil, nil, 0, 0, fmt.Errorf("sign: %w", err)
	}

	if len(resp) < 1 || resp[0] == msgFailure {
		return nil, nil, 0, 0, fmt.Errorf("sign: rejected by phone")
	}
	if resp[0] != msgSKSignResponse {
		return nil, nil, 0, 0, fmt.Errorf("sign: unexpected response type %d", resp[0])
	}
	if len(resp) < 1+64+4+1 {
		return nil, nil, 0, 0, fmt.Errorf("sign: response too short (%d bytes)", len(resp))
	}

	raw := resp[1:65]
	counter = binary.BigEndian.Uint32(resp[65:69])
	respFlags = resp[69]

	if alg == 0 {
		sigR = make([]byte, 32)
		sigS = make([]byte, 32)
		copy(sigR, raw[0:32])
		copy(sigS, raw[32:64])
	} else {
		sigR = make([]byte, 64)
		copy(sigR, raw)
	}

	log.Printf("[SK-TERMUX] Sign succeeded: alg=%d counter=%d flags=0x%02x", alg, counter, respFlags)
	return sigR, sigS, counter, respFlags, nil
}

type ResidentKey struct {
	Alg    uint32
	App    string
	PubKey []byte
	Handle []byte
	Flags  byte
}

func (b *ContentBackend) LoadResidentKeys() ([]ResidentKey, error) {
	msg := []byte{msgSKLoadResidentRequest}
	resp, err := b.SendMessage(msg, defaultTimeout)
	if err != nil {
		return nil, fmt.Errorf("load resident keys: %w", err)
	}

	if len(resp) < 1 || resp[0] == msgFailure {
		return nil, fmt.Errorf("load resident keys: rejected by phone")
	}
	if resp[0] != msgSKLoadResidentResponse {
		return nil, fmt.Errorf("load resident keys: unexpected response type %d", resp[0])
	}
	if len(resp) < 3 {
		return nil, fmt.Errorf("load resident keys: response too short")
	}

	numKeys := int(binary.BigEndian.Uint16(resp[1:3]))
	off := 3
	keys := make([]ResidentKey, 0, numKeys)

	for i := 0; i < numKeys; i++ {
		if off >= len(resp) {
			return nil, fmt.Errorf("load resident keys: truncated at key %d", i)
		}
		alg := uint32(resp[off]); off++

		if off+2 > len(resp) { return nil, fmt.Errorf("load resident keys: truncated at key %d app len", i) }
		appLen := int(binary.BigEndian.Uint16(resp[off:])); off += 2
		if off+appLen > len(resp) { return nil, fmt.Errorf("load resident keys: truncated at key %d app", i) }
		app := string(resp[off : off+appLen]); off += appLen

		if off+2 > len(resp) { return nil, fmt.Errorf("load resident keys: truncated at key %d pubkey len", i) }
		pubLen := int(binary.BigEndian.Uint16(resp[off:])); off += 2
		if off+pubLen > len(resp) { return nil, fmt.Errorf("load resident keys: truncated at key %d pubkey", i) }
		pubKey := make([]byte, pubLen); copy(pubKey, resp[off:off+pubLen]); off += pubLen

		if off+2 > len(resp) { return nil, fmt.Errorf("load resident keys: truncated at key %d handle len", i) }
		handleLen := int(binary.BigEndian.Uint16(resp[off:])); off += 2
		if off+handleLen > len(resp) { return nil, fmt.Errorf("load resident keys: truncated at key %d handle", i) }
		handle := make([]byte, handleLen); copy(handle, resp[off:off+handleLen]); off += handleLen

		if off >= len(resp) { return nil, fmt.Errorf("load resident keys: truncated at key %d flags", i) }
		flags := resp[off]; off++

		keys = append(keys, ResidentKey{Alg: alg, App: app, PubKey: pubKey, Handle: handle, Flags: flags})
	}

	log.Printf("[SK-TERMUX] Loaded %d resident keys", len(keys))
	return keys, nil
}
