package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	msgSKEnrollRequest  byte = 103
	msgSKEnrollResponse byte = 104
	msgSKSignRequest    byte = 105
	msgSKSignResponse   byte = 106
	msgFailure          byte = 5

	packageName = "com.example.pocketsshagent"
	bridgeClass = "com.example.pocketsshagent.termux.PocketAgentBridge"
)

type PipeBackend struct {
	mu     sync.Mutex
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
}

var (
	globalBackend *PipeBackend
	backendMu     sync.Mutex
)

func getBackend() *PipeBackend {
	backendMu.Lock()
	defer backendMu.Unlock()
	if globalBackend != nil && globalBackend.cmd.ProcessState == nil {
		return globalBackend
	}
	globalBackend = nil
	b, err := startBackend()
	if err != nil {
		log.Printf("[SK-TERMUX] Failed to start backend: %v", err)
		return nil
	}
	globalBackend = b
	return globalBackend
}

func discoverAPKPath() (string, error) {
	out, err := exec.Command("pm", "path", packageName).Output()
	if err != nil {
		return "", fmt.Errorf("pm path %s: %w", packageName, err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "package:") {
			return strings.TrimPrefix(line, "package:"), nil
		}
	}
	return "", fmt.Errorf("no APK found for %s", packageName)
}

func startBackend() (*PipeBackend, error) {
	apkPath, err := discoverAPKPath()
	if err != nil {
		return nil, err
	}

	log.Printf("[SK-TERMUX] APK path: %s", apkPath)

	cmd := exec.Command("app_process", "/", bridgeClass)
	cmd.Env = append(os.Environ(), "CLASSPATH="+apkPath)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		stdin.Close()
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		stdin.Close()
		stdout.Close()
		return nil, fmt.Errorf("stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start app_process: %w", err)
	}

	ready := make(chan struct{})
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			log.Printf("[bridge] %s", line)
			if line == "READY" {
				close(ready)
			}
		}
	}()

	select {
	case <-ready:
		log.Printf("[SK-TERMUX] Bridge is ready")
	case <-time.After(30 * time.Second):
		cmd.Process.Kill()
		return nil, fmt.Errorf("bridge did not become ready within 30s")
	}

	return &PipeBackend{cmd: cmd, stdin: stdin, stdout: stdout}, nil
}

func (b *PipeBackend) SendMessage(msg []byte) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(msg)))
	if _, err := b.stdin.Write(header); err != nil {
		return nil, fmt.Errorf("write header: %w", err)
	}
	if _, err := b.stdin.Write(msg); err != nil {
		return nil, fmt.Errorf("write message: %w", err)
	}

	if _, err := io.ReadFull(b.stdout, header); err != nil {
		return nil, fmt.Errorf("read response header: %w", err)
	}
	respLen := binary.BigEndian.Uint32(header)
	if respLen == 0 || respLen > 65536 {
		return nil, fmt.Errorf("invalid response length: %d", respLen)
	}

	resp := make([]byte, respLen)
	if _, err := io.ReadFull(b.stdout, resp); err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	return resp, nil
}

func (b *PipeBackend) Enroll(application string, alg uint32, flags byte, label string, challenge []byte) (pubkey, keyHandle []byte, actualAlg uint32, attestationChain [][]byte, err error) {
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

	resp, err := b.SendMessage(msg)
	if err != nil {
		return nil, nil, 0, nil, fmt.Errorf("enroll: send failed: %w", err)
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

func (b *PipeBackend) Sign(alg uint32, application string, keyHandle, data []byte, flags byte) (sigR, sigS []byte, counter uint32, respFlags byte, err error) {
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
	resp, err := b.SendMessage(msg)
	if err != nil {
		return nil, nil, 0, 0, fmt.Errorf("sign: send failed: %w", err)
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
