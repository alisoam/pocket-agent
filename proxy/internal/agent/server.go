package agent

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
)

// Server implements an SSH agent socket server that proxies requests
// to the phone over BLE.
type Server struct {
	socketPath string
	listener   net.Listener
	transport  Transport
	mu         sync.Mutex
}

// Transport is the interface for sending agent messages to the phone
// and receiving responses.
type Transport interface {
	// SendMessage sends a raw agent message (without length prefix) and
	// returns the response (without length prefix).
	SendMessage(msg []byte) ([]byte, error)
}

// NewServer creates a new SSH agent socket server.
func NewServer(socketPath string, transport Transport) *Server {
	return &Server{
		socketPath: socketPath,
		transport:  transport,
	}
}

// Start begins listening on the Unix socket.
func (s *Server) Start() error {
	// Remove existing socket file
	os.Remove(s.socketPath)

	listener, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.socketPath, err)
	}
	s.listener = listener

	// Set socket permissions (owner only)
	if err := os.Chmod(s.socketPath, 0600); err != nil {
		listener.Close()
		return fmt.Errorf("failed to chmod socket: %w", err)
	}

	log.Printf("SSH agent listening on %s", s.socketPath)
	log.Printf("Export with: export SSH_AUTH_SOCK=%s", s.socketPath)

	go s.acceptLoop()
	return nil
}

// Stop closes the listener and removes the socket file.
func (s *Server) Stop() {
	if s.listener != nil {
		s.listener.Close()
	}
	os.Remove(s.socketPath)
}

// SocketPath returns the path to the Unix socket.
func (s *Server) SocketPath() string {
	return s.socketPath
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return // listener closed
		}
		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	for {
		// Read length-prefixed message from SSH client
		msg, err := readAgentMessage(conn)
		if err != nil {
			if err != io.EOF {
				log.Printf("Error reading from client: %v", err)
			}
			return
		}

		if len(msg) > 0 {
			log.Printf("agent: incoming msg type=%d len=%d", msg[0], len(msg))
		}

		// Pre-hash ECDSA data so Android can sign with NONEwithECDSA
		// (same path as PKCS#11; OpenSSH agent protocol sends unhashed data)
		msg = prehashECDSASignRequest(msg)

		// Forward to phone via BLE transport
		s.mu.Lock()
		response, err := s.transport.SendMessage(msg)
		s.mu.Unlock()

		if err != nil {
			log.Printf("Transport error: %v (may be reconnecting)", err)
			// Send failure response
			writeAgentMessage(conn, []byte{5}) // SSH_AGENT_FAILURE
			continue
		}

		if len(response) > 0 {
			log.Printf("agent: response type=%d len=%d", response[0], len(response))
		}

		// Write response back to SSH client
		if err := writeAgentMessage(conn, response); err != nil {
			log.Printf("Error writing to client: %v", err)
			return
		}
	}
}

// readAgentMessage reads a length-prefixed SSH agent message.
func readAgentMessage(r io.Reader) ([]byte, error) {
	var length uint32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, err
	}
	if length > 256*1024 {
		return nil, fmt.Errorf("message too large: %d bytes", length)
	}
	msg := make([]byte, length)
	if _, err := io.ReadFull(r, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

// writeAgentMessage writes a length-prefixed SSH agent message.
func writeAgentMessage(w io.Writer, msg []byte) error {
	length := uint32(len(msg))
	if err := binary.Write(w, binary.BigEndian, length); err != nil {
		return err
	}
	_, err := w.Write(msg)
	return err
}

// prehashECDSASignRequest replaces the data field in an SSH_AGENTC_SIGN_REQUEST
// with its SHA-256 hash when the key is ecdsa-sha2-nistp256. Android signs with
// NONEwithECDSA (no re-hashing), so we must pre-hash here — matching the PKCS#11 path.
func prehashECDSASignRequest(msg []byte) []byte {
	const signRequestType = 13
	const ecdsaKeyType = "ecdsa-sha2-nistp256"

	if len(msg) < 5 || msg[0] != signRequestType {
		return msg
	}

	offset := 1

	// Parse key blob
	if offset+4 > len(msg) {
		return msg
	}
	kbLen := int(binary.BigEndian.Uint32(msg[offset:]))
	offset += 4
	if offset+kbLen > len(msg) {
		return msg
	}
	keyBlob := msg[offset : offset+kbLen]
	offset += kbLen

	// Check key type string inside the blob
	if len(keyBlob) < 4 {
		return msg
	}
	typeLen := int(binary.BigEndian.Uint32(keyBlob[:4]))
	if typeLen != len(ecdsaKeyType) || len(keyBlob) < 4+typeLen {
		return msg
	}
	if string(keyBlob[4:4+typeLen]) != ecdsaKeyType {
		return msg
	}

	// Parse data field
	if offset+4 > len(msg) {
		return msg
	}
	dataLen := int(binary.BigEndian.Uint32(msg[offset:]))
	offset += 4
	if offset+dataLen > len(msg) {
		return msg
	}
	data := msg[offset : offset+dataLen]
	offset += dataLen

	// Parse flags
	if offset+4 > len(msg) {
		return msg
	}
	flags := msg[offset : offset+4]

	if dataLen == 32 {
		// Already hashed (e.g. future-proof or re-entry), skip
		return msg
	}

	hash := sha256.Sum256(data)
	log.Printf("agent: pre-hashed ECDSA P-256 sign data: %d -> 32 bytes", dataLen)

	out := make([]byte, 0, 1+4+kbLen+4+32+4)
	out = append(out, signRequestType)
	out = binary.BigEndian.AppendUint32(out, uint32(kbLen))
	out = append(out, keyBlob...)
	out = binary.BigEndian.AppendUint32(out, 32)
	out = append(out, hash[:]...)
	out = append(out, flags...)
	return out
}
