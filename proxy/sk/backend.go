package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/example/pocket-agent-proxy/internal/ble"
)

const (
	msgSKEnrollRequest  byte = 103
	msgSKEnrollResponse byte = 104
	msgSKSignRequest    byte = 105
	msgSKSignResponse          byte = 106
	msgSKLoadResidentRequest   byte = 107
	msgSKLoadResidentResponse  byte = 108
	msgFailure                 byte = 5
)

// SKBackend manages BLE communication for the SK provider.
type SKBackend struct {
	connMgr *ble.ConnectionManager
}

var (
	globalSKBackend *SKBackend
	skMu            sync.Mutex
)

func initSK(privateKey ed25519.PrivateKey) error {
	skMu.Lock()
	defer skMu.Unlock()

	if globalSKBackend != nil {
		return nil
	}

	connMgr := ble.NewConnectionManager(privateKey)
	globalSKBackend = &SKBackend{connMgr: connMgr}

	if err := connMgr.Start(); err != nil {
		globalSKBackend = nil
		return fmt.Errorf("failed to start BLE: %w", err)
	}

	return nil
}

func finalizeSK() {
	skMu.Lock()
	defer skMu.Unlock()

	if globalSKBackend != nil {
		globalSKBackend.connMgr.Stop()
		globalSKBackend = nil
	}
}

func getSKBackend() *SKBackend {
	skMu.Lock()
	defer skMu.Unlock()
	return globalSKBackend
}

func (b *SKBackend) ensureConnected() error {
	if b.connMgr.IsConnected() {
		return nil
	}
	log.Println("[SK] Waiting for BLE connection to Android (open the app if not running)...")
	if err := b.connMgr.WaitUntilConnected(60 * time.Second); err != nil {
		return fmt.Errorf("BLE not ready: %w", err)
	}
	return nil
}

// Enroll asks the phone to generate a new key and returns the raw public key and key handle.
// alg: 0=ECDSA P-256 (65-byte EC point), 1=Ed25519 (32-byte key).
// label is a human-readable name shown in the Android app (empty = use a default).
//
// Message to phone — SK_ENROLL_REQUEST (103):
//
//	[type:1=103][alg:1][app_hash:32][flags:1][label_len:2][label:N][chal_len:2][challenge:N]
//
// Response from phone — SK_ENROLL_RESPONSE (104):
//
//	[type:1=104][actual_alg:1][pubkey_len:2][pubkey:N][handle_len:2][handle:N]
//	[cert_count:1] {[cert_len:2][cert:N]}*
//
// actual_alg may differ from alg on devices where Android Keystore silently
// falls back to ECDSA when Ed25519 is unavailable. In that case the phone
// deletes the key and returns failure (type 5) instead, so callers only see
// actual_alg in successful responses — but it is always verified here.
//
// When challenge is non-empty and alg is ECDSA, the phone returns the hardware
// attestation cert chain (leaf-first, rooted in Google's attestation root).
// For Ed25519 or empty challenge, attestationChain is empty.
func (b *SKBackend) Enroll(application string, alg uint32, flags byte, label string, challenge []byte) (pubkey, keyHandle []byte, actualAlg uint32, attestationChain [][]byte, err error) {
	if err = b.ensureConnected(); err != nil {
		return
	}

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

	resp, err := b.connMgr.SendMessage(msg)
	if err != nil {
		return nil, nil, 0, nil, fmt.Errorf("enroll: BLE send failed: %w", err)
	}

	if len(resp) < 1 || resp[0] == msgFailure {
		return nil, nil, 0, nil, fmt.Errorf("enroll: rejected by phone (device may not support requested algorithm)")
	}
	if resp[0] != msgSKEnrollResponse {
		return nil, nil, 0, nil, fmt.Errorf("enroll: unexpected response type %d", resp[0])
	}

	if len(resp) < 1+1+2 {
		return nil, nil, 0, nil, fmt.Errorf("enroll: response too short (%d bytes)", len(resp))
	}
	actualAlg = uint32(resp[1])
	if actualAlg != alg {
		log.Printf("[SK] Enroll: phone returned alg=%d but %d was requested", actualAlg, alg)
	}

	pubkeyLen := int(binary.BigEndian.Uint16(resp[2:4]))
	if len(resp) < 1+1+2+pubkeyLen+2 {
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

	// Optional attestation chain (older phones may omit).
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

	log.Printf("[SK] Enroll succeeded: requested_alg=%d actual_alg=%d handle=%q pubkey=%x… attestation_certs=%d",
		alg, actualAlg, string(keyHandle), pubkey[:4], len(attestationChain))
	return pubkey, keyHandle, actualAlg, attestationChain, nil
}

// Sign asks the phone to sign an SSH challenge with the key identified by keyHandle.
// It sends pre-hashed components; the phone embeds the counter and signs the 69-byte
// FIDO2 input (appHash || flags || counter_BE32 || dataHash).
//
// For Ed25519 (alg=1): sigR is the full 64-byte signature, sigS is nil.
// For ECDSA P-256 (alg=0): sigR and sigS are the raw 32-byte R and S components.
//
// Message to phone — SK_SIGN_REQUEST (105):
//
//	[type:1=105][handle_len:2][handle:N][app_hash:32][flags:1][data_hash:32]
//
// Response from phone — SK_SIGN_RESPONSE (106):
//
//	[type:1=106][sig:64][counter:4][flags:1]
//	  Ed25519: sig[0:64] = full signature
//	  ECDSA:   sig[0:32] = R, sig[32:64] = S
func (b *SKBackend) Sign(alg uint32, application string, keyHandle, data []byte, flags byte) (sigR, sigS []byte, counter uint32, respFlags byte, err error) {
	if err = b.ensureConnected(); err != nil {
		return
	}

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

	log.Println("[SK] Sending SK sign request to Android (will trigger biometric)...")
	resp, err := b.connMgr.SendMessage(msg)
	if err != nil {
		return nil, nil, 0, 0, fmt.Errorf("sign: BLE send failed: %w", err)
	}

	if len(resp) < 1 || resp[0] == msgFailure {
		return nil, nil, 0, 0, fmt.Errorf("sign: rejected by phone")
	}
	if resp[0] != msgSKSignResponse {
		return nil, nil, 0, 0, fmt.Errorf("sign: unexpected response type %d", resp[0])
	}

	// [type:1][sig:64][counter:4][flags:1]
	if len(resp) < 1+64+4+1 {
		return nil, nil, 0, 0, fmt.Errorf("sign: response too short (%d bytes)", len(resp))
	}

	raw := resp[1:65]
	counter = binary.BigEndian.Uint32(resp[65:69])
	respFlags = resp[69]

	if alg == 0 { // SSH_SK_ECDSA: split into R and S
		sigR = make([]byte, 32)
		sigS = make([]byte, 32)
		copy(sigR, raw[0:32])
		copy(sigS, raw[32:64])
	} else { // SSH_SK_ED25519: full 64-byte signature in sigR
		sigR = make([]byte, 64)
		copy(sigR, raw)
	}

	log.Printf("[SK] Sign succeeded: alg=%d counter=%d flags=0x%02x", alg, counter, respFlags)
	return sigR, sigS, counter, respFlags, nil
}

type ResidentKey struct {
	Alg    uint32
	App    string
	PubKey []byte
	Handle []byte
	Flags  byte
}

func (b *SKBackend) LoadResidentKeys() ([]ResidentKey, error) {
	if err := b.ensureConnected(); err != nil {
		return nil, err
	}

	msg := []byte{msgSKLoadResidentRequest}
	resp, err := b.connMgr.SendMessage(msg)
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

	log.Printf("[SK] Loaded %d resident keys", len(keys))
	return keys, nil
}
