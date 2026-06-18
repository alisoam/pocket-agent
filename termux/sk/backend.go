package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
	"os/exec"
	"regexp"
	"strings"
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

	broadcastAction = "com.example.pocketsshagent.HANDLE_MESSAGE"
	signTimeout     = 90 * time.Second
	defaultTimeout  = 15 * time.Second
)

type BroadcastBackend struct{}

var globalBackend = &BroadcastBackend{}

func getBackend() *BroadcastBackend {
	return globalBackend
}

func (b *BroadcastBackend) SendMessage(msg []byte, timeout time.Duration) ([]byte, error) {
	requestB64 := base64.StdEncoding.EncodeToString(msg)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "/system/bin/am", "broadcast",
		"--user", "0",
		"-n", "com.example.pocketsshagent/.termux.AgentReceiver",
		"--es", "msg", requestB64)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	out, err := cmd.Output()
	if stderrStr := stderr.String(); stderrStr != "" {
		log.Printf("[SK-TERMUX] am broadcast stderr: %s", stderrStr)
	}
	log.Printf("[SK-TERMUX] am broadcast stdout: %q (err=%v)", string(out), err)
	if err != nil {
		return nil, fmt.Errorf("am broadcast: %w", err)
	}

	responseB64, err := parseBroadcastOutput(string(out))
	if err != nil {
		return nil, err
	}

	framed, err := base64.StdEncoding.DecodeString(responseB64)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	if len(framed) < 4 {
		return nil, fmt.Errorf("response too short (%d bytes)", len(framed))
	}
	return framed[4:], nil
}

var broadcastDataRe = regexp.MustCompile(`data="([A-Za-z0-9+/=]+)"`)

func parseBroadcastOutput(output string) (string, error) {
	output = strings.TrimSpace(output)
	if strings.Contains(output, "without waiting") {
		return "", fmt.Errorf("broadcast sent async, ordered broadcast required: %s", output)
	}

	m := broadcastDataRe.FindStringSubmatch(output)
	if m == nil {
		return "", fmt.Errorf("no result data in broadcast output: %s", output)
	}
	return m[1], nil
}

func (b *BroadcastBackend) Enroll(application string, alg uint32, flags byte, label string, challenge []byte) (pubkey, keyHandle []byte, actualAlg uint32, attestationChain [][]byte, err error) {
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

func (b *BroadcastBackend) Sign(alg uint32, application string, keyHandle, data []byte, flags byte) (sigR, sigS []byte, counter uint32, respFlags byte, err error) {
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

func (b *BroadcastBackend) LoadResidentKeys() ([]ResidentKey, error) {
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
