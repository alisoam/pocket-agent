package agent

import (
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

		// Forward to phone via BLE transport
		s.mu.Lock()
		response, err := s.transport.SendMessage(msg)
		s.mu.Unlock()

		if err != nil {
			log.Printf("Error from transport: %v", err)
			// Send failure response
			writeAgentMessage(conn, []byte{5}) // SSH_AGENT_FAILURE
			continue
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
