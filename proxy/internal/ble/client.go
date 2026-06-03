package ble

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"log"
	"sync"
	"time"

	"tinygo.org/x/bluetooth"
)

var (
	ServiceUUID = bluetooth.NewUUID([16]byte{
		0xa1, 0x1e, 0x1f, 0x4e, 0xc8, 0xa0, 0x4d, 0x3b,
		0x9f, 0x6a, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f,
	})
	RxUUID = bluetooth.NewUUID([16]byte{
		0xa1, 0x2e, 0x1f, 0x4e, 0xc8, 0xa0, 0x4d, 0x3b,
		0x9f, 0x6a, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x70,
	})
	TxUUID = bluetooth.NewUUID([16]byte{
		0xa1, 0x2e, 0x1f, 0x4e, 0xc8, 0xa0, 0x4d, 0x3b,
		0x9f, 0x6a, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x71,
	})
	CCCDUUID = bluetooth.NewUUID([16]byte{
		0x00, 0x00, 0x29, 0x02, 0x00, 0x00, 0x10, 0x00,
		0x80, 0x00, 0x00, 0x80, 0x5f, 0x9b, 0x34, 0xfb,
	})
)

// Client is a BLE GATT client that connects to the phone's SSH agent service.
type Client struct {
	adapter *bluetooth.Adapter
	device  bluetooth.Device
	rxChar  bluetooth.DeviceCharacteristic
	txChar  bluetooth.DeviceCharacteristic
	mtu     int

	responseCh chan []byte
	rxBuf      []byte
	rxExpected int
	rxMu       sync.Mutex

	connected bool
	mu        sync.Mutex
}

// NewClient creates a new BLE client.
func NewClient() *Client {
	return &Client{
		adapter:    bluetooth.DefaultAdapter,
		mtu:        20,
		responseCh: make(chan []byte, 1),
	}
}

// Connect scans for and connects to the phone's SSH agent BLE service.
func (c *Client) Connect() error {
	if err := c.adapter.Enable(); err != nil {
		return fmt.Errorf("failed to enable BLE adapter: %w", err)
	}

	log.Println("Scanning for SSH Agent BLE service...")

	var foundDevice bluetooth.ScanResult
	found := make(chan struct{})

	err := c.adapter.Scan(func(adapter *bluetooth.Adapter, result bluetooth.ScanResult) {
		if result.HasServiceUUID(ServiceUUID) {
			foundDevice = result
			adapter.StopScan()
			close(found)
		}
	})
	if err != nil {
		// Scan returns after StopScan
		select {
		case <-found:
		default:
			return fmt.Errorf("scan failed: %w", err)
		}
	}

	select {
	case <-found:
	case <-time.After(30 * time.Second):
		c.adapter.StopScan()
		return fmt.Errorf("timeout: no SSH agent device found")
	}

	log.Printf("Found device: %s (%s)", foundDevice.LocalName(), foundDevice.Address.String())

	device, err := c.adapter.Connect(foundDevice.Address, bluetooth.ConnectionParams{})
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	c.device = device

	// Discover services
	services, err := device.DiscoverServices([]bluetooth.UUID{ServiceUUID})
	if err != nil {
		return fmt.Errorf("failed to discover services: %w", err)
	}
	if len(services) == 0 {
		return fmt.Errorf("SSH agent service not found on device")
	}

	// Discover characteristics
	chars, err := services[0].DiscoverCharacteristics([]bluetooth.UUID{RxUUID, TxUUID})
	if err != nil {
		return fmt.Errorf("failed to discover characteristics: %w", err)
	}

	for _, ch := range chars {
		switch ch.UUID() {
		case RxUUID:
			c.rxChar = ch
		case TxUUID:
			c.txChar = ch
		}
	}

	// Subscribe to TX notifications
	if err := c.txChar.EnableNotifications(c.handleNotification); err != nil {
		return fmt.Errorf("failed to enable TX notifications: %w", err)
	}

	c.mu.Lock()
	c.connected = true
	c.mu.Unlock()

	log.Println("Connected to SSH Agent BLE service")
	return nil
}

// Authenticate sends a POCKET_AUTH_REQUEST to the phone.
// The phone verifies the signature and checks its trust store.
// Returns nil on success, error if rejected.
func (c *Client) Authenticate(privateKey ed25519.PrivateKey) error {
	// Generate random nonce
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Sign the nonce
	signature := ed25519.Sign(privateKey, nonce)

	// Encode public key as X.509
	publicKey := privateKey.Public().(ed25519.PublicKey)
	x509PubKey, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}

	// Build auth message: byte(100) | string(pubkey) | string(nonce) | string(signature)
	msg := []byte{100} // POCKET_AUTH_REQUEST
	msg = append(msg, encodeString(x509PubKey)...)
	msg = append(msg, encodeString(nonce)...)
	msg = append(msg, encodeString(signature)...)

	response, err := c.SendMessage(msg)
	if err != nil {
		return fmt.Errorf("auth request failed: %w", err)
	}

	if len(response) == 0 {
		return fmt.Errorf("empty auth response")
	}

	switch response[0] {
	case 101: // POCKET_AUTH_SUCCESS
		log.Println("Authentication successful")
		return nil
	case 102: // POCKET_AUTH_FAILURE
		return fmt.Errorf("authentication rejected: device not trusted (removed from phone?)")
	default:
		return fmt.Errorf("unexpected auth response: %d", response[0])
	}
}

func encodeString(data []byte) []byte {
	buf := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(buf[0:4], uint32(len(data)))
	copy(buf[4:], data)
	return buf
}

// SendMessage sends an agent message and waits for the response.
// Implements the agent.Transport interface.
func (c *Client) SendMessage(msg []byte) ([]byte, error) {
	c.mu.Lock()
	if !c.connected {
		c.mu.Unlock()
		return nil, fmt.Errorf("not connected")
	}
	c.mu.Unlock()

	// Frame the message (4-byte length prefix + payload)
	framed := make([]byte, 4+len(msg))
	binary.BigEndian.PutUint32(framed[0:4], uint32(len(msg)))
	copy(framed[4:], msg)

	// Send in MTU-sized chunks
	log.Printf("BLE: sending message (%d bytes, type=%d) in %d-byte chunks", len(msg), msg[0], c.mtu)
	for offset := 0; offset < len(framed); offset += c.mtu {
		end := offset + c.mtu
		if end > len(framed) {
			end = len(framed)
		}
		chunk := framed[offset:end]
		_, err := c.rxChar.WriteWithoutResponse(chunk)
		if err != nil {
			return nil, fmt.Errorf("failed to write chunk: %w", err)
		}
	}

	// Wait for response
	select {
	case response := <-c.responseCh:
		return response, nil
	case <-time.After(30 * time.Second):
		return nil, fmt.Errorf("timeout waiting for response")
	}
}

// Disconnect closes the BLE connection.
func (c *Client) Disconnect() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.connected {
		c.device.Disconnect()
		c.connected = false
	}
}

func (c *Client) handleNotification(buf []byte) {
	c.rxMu.Lock()
	defer c.rxMu.Unlock()

	c.rxBuf = append(c.rxBuf, buf...)

	// Need at least 4 bytes for length
	if len(c.rxBuf) < 4 {
		return
	}

	if c.rxExpected == 0 {
		c.rxExpected = int(binary.BigEndian.Uint32(c.rxBuf[0:4]))
	}

	totalNeeded := 4 + c.rxExpected
	if len(c.rxBuf) < totalNeeded {
		return
	}

	// Complete response received
	message := make([]byte, c.rxExpected)
	copy(message, c.rxBuf[4:totalNeeded])

	// Reset
	c.rxBuf = nil
	c.rxExpected = 0

	log.Printf("BLE: received response (%d bytes, type=%d)", len(message), message[0])

	// Send to waiting caller
	select {
	case c.responseCh <- message:
	default:
		log.Println("Warning: response dropped (no receiver)")
	}
}
