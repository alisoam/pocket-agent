package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"
)

const (
	msgSKEnrollRequest  byte = 103
	msgSKEnrollResponse byte = 104
	msgSKSignRequest    byte = 105
	msgSKSignResponse   byte = 106
	msgFailure          byte = 5

	contentAuthority = "content://com.example.pocketsshagent.agent"
	signTimeout      = 90 * time.Second
	defaultTimeout   = 15 * time.Second
)

type ContentBackend struct{}

var globalBackend = &ContentBackend{}

func getBackend() *ContentBackend {
	return globalBackend
}

func (b *ContentBackend) SendMessage(msg []byte, timeout time.Duration) ([]byte, error) {
	requestB64 := base64.StdEncoding.EncodeToString(msg)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "/system/bin/content", "call",
		"--uri", contentAuthority,
		"--method", "handleMessage",
		"--arg", requestB64)

	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("content call: %w", err)
	}

	responseB64, err := parseContentCallOutput(string(out))
	if err != nil {
		return nil, err
	}

	return base64.StdEncoding.DecodeString(responseB64)
}

func parseContentCallOutput(output string) (string, error) {
	output = strings.TrimSpace(output)
	prefix := "Result: Bundle[{"
	if !strings.HasPrefix(output, prefix) {
		return "", fmt.Errorf("unexpected content call output: %s", output)
	}

	inner := output[len(prefix):]
	idx := strings.Index(inner, "}]")
	if idx < 0 {
		return "", fmt.Errorf("malformed content call output: %s", output)
	}
	inner = inner[:idx]

	for _, pair := range strings.Split(inner, ", ") {
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) == 2 && parts[0] == "r" {
			return parts[1], nil
		}
	}
	return "", fmt.Errorf("no 'r' key in content call output: %s", output)
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
