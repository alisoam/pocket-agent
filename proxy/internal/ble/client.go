package ble

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
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

	responseCh    chan []byte
	rxBuf         []byte
	rxExpected    int
	pendingCorrID [4]byte // protected by rxMu
	rxMu          sync.Mutex

	connected     bool
	scanning      bool     // true while adapter.Scan is in progress; protected by mu
	sessionActive bool     // true after ECDH key exchange; protected by mu
	sessionKey    [32]byte // AES-256-GCM session key; protected by mu
	mu            sync.Mutex
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

	// Ensure any previous scan is stopped
	c.adapter.StopScan()
	// Give the adapter time to fully stop the scan
	time.Sleep(50 * time.Millisecond)

	log.Println("Scanning for SSH Agent BLE service...")

	var foundDevice bluetooth.ScanResult
	found := make(chan struct{})

	c.mu.Lock()
	c.scanning = true
	c.mu.Unlock()

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
			c.mu.Lock()
			c.scanning = false
			c.mu.Unlock()
			return fmt.Errorf("scan failed: %w", err)
		}
	}

	select {
	case <-found:
	case <-time.After(10 * time.Second):
		c.adapter.StopScan()
		c.mu.Lock()
		c.scanning = false
		c.mu.Unlock()
		return fmt.Errorf("timeout: no SSH agent device found after 10s scan")
	}

	c.mu.Lock()
	c.scanning = false
	c.mu.Unlock()

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
	log.Println("Enabling TX notifications...")
	if err := c.txChar.EnableNotifications(c.handleNotification); err != nil {
		return fmt.Errorf("failed to enable TX notifications: %w", err)
	}
	log.Println("TX notifications enabled successfully, waiting for events...")

	// Delay to ensure notification subscription is fully set up
	// and the BLE stack is ready to receive notifications.
	time.Sleep(500 * time.Millisecond)

	c.mu.Lock()
	c.connected = true
	c.mu.Unlock()

	log.Println("Connected to SSH Agent BLE service")

	return nil
}

// Authenticate sends a POCKET_AUTH_REQUEST to the phone and performs an
// ephemeral ECDH key exchange to establish a per-session AES-256-GCM key.
//
// Protocol (type 100 request):
//
//	byte(100) | string(x509_pubkey) | string(nonce) | string(ed25519_sig) | string(x25519_ephemeral_pub)
//
// Protocol (type 101 success response):
//
//	byte(101) | string(x25519_ephemeral_pub_phone)
//
// After this call all messages sent via SendMessage are encrypted with
// AES-256-GCM using a key derived from the ECDH shared secret.
func (c *Client) Authenticate(privateKey ed25519.PrivateKey) error {
	// Generate random nonce (also used as HKDF salt)
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

	// Generate ephemeral X25519 keypair for ECDH
	ephemPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate X25519 key: %w", err)
	}
	ephemPub := ephemPriv.PublicKey().Bytes() // 32 bytes

	// Build auth message: byte(100) | string(pubkey) | string(nonce) | string(sig) | string(x25519_pub)
	msg := []byte{100} // POCKET_AUTH_REQUEST
	msg = append(msg, encodeString(x509PubKey)...)
	msg = append(msg, encodeString(nonce)...)
	msg = append(msg, encodeString(signature)...)
	msg = append(msg, encodeString(ephemPub)...)

	// SendMessage is called before sessionActive=true, so this goes out plaintext.
	response, err := c.SendMessage(msg)
	if err != nil {
		return fmt.Errorf("auth request failed: %w", err)
	}

	if len(response) == 0 {
		return fmt.Errorf("empty auth response")
	}

	switch response[0] {
	case 101: // POCKET_AUTH_SUCCESS — response carries phone's X25519 ephemeral pubkey
		if len(response) < 5 {
			return fmt.Errorf("auth success response missing X25519 key")
		}
		keyLen := int(binary.BigEndian.Uint32(response[1:5]))
		if len(response) < 5+keyLen {
			return fmt.Errorf("auth success response X25519 key truncated")
		}
		phonePub, err := ecdh.X25519().NewPublicKey(response[5 : 5+keyLen])
		if err != nil {
			return fmt.Errorf("invalid phone X25519 key: %w", err)
		}

		shared, err := ephemPriv.ECDH(phonePub)
		if err != nil {
			return fmt.Errorf("ECDH failed: %w", err)
		}

		derived := deriveSessionKey(shared, nonce)

		c.mu.Lock()
		c.sessionKey = derived
		c.sessionActive = true
		c.mu.Unlock()

		log.Println("Authentication successful — session key established (AES-256-GCM)")
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
// When a session key is active (post-Authenticate) the payload is encrypted
// with AES-256-GCM and the response is decrypted before returning.
func (c *Client) SendMessage(msg []byte) ([]byte, error) {
	c.mu.Lock()
	if !c.connected {
		c.mu.Unlock()
		return nil, fmt.Errorf("not connected")
	}
	active := c.sessionActive
	key := c.sessionKey // copy while holding mu
	c.mu.Unlock()

	// Drain any stale response left from a previous operation (e.g. a late
	// IDENTITIES_ANSWER arriving after LoadKeys already returned).
	select {
	case stale := <-c.responseCh:
		log.Printf("BLE: drained stale response (type=%d, %d bytes) before sending", stale[0], len(stale))
	default:
	}

	// Generate a correlation ID so this client can ignore responses destined
	// for other clients sharing the same underlying BLE connection/notifications.
	var corrID [4]byte
	if _, err := rand.Read(corrID[:]); err != nil {
		return nil, fmt.Errorf("failed to generate correlation ID: %w", err)
	}
	c.rxMu.Lock()
	c.pendingCorrID = corrID
	c.rxMu.Unlock()

	// Encrypt the message when a session key is active.
	outgoing := msg
	if active {
		var err error
		outgoing, err = sealAESGCM(key, msg)
		if err != nil {
			return nil, fmt.Errorf("encrypt: %w", err)
		}
	}

	// Frame: [4B ble_len][4B corr_id][outgoing]
	payload := make([]byte, 4+len(outgoing))
	copy(payload[:4], corrID[:])
	copy(payload[4:], outgoing)
	framed := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(framed[0:4], uint32(len(payload)))
	copy(framed[4:], payload)

	// Send in MTU-sized chunks
	log.Printf("BLE: sending message (%d bytes, type=%d, encrypted=%v) in %d-byte chunks", len(msg), msg[0], active, c.mtu)
	for offset := 0; offset < len(framed); offset += c.mtu {
		end := offset + c.mtu
		if end > len(framed) {
			end = len(framed)
		}
		chunk := framed[offset:end]
		_, err := c.rxChar.WriteWithoutResponse(chunk)
		if err != nil {
			// Mark as disconnected so subsequent operations fail fast instead of
			// repeatedly attempting writes to a dead connection
			c.mu.Lock()
			c.connected = false
			c.mu.Unlock()
			return nil, fmt.Errorf("BLE write failed (connection lost?): %w", err)
		}
	}

	// Wait for response — sign requests need extra time for notification tap + biometric
	timeout := 10 * time.Second
	if len(msg) > 0 && msg[0] == 13 { // SSH_AGENTC_SIGN_REQUEST
		timeout = 60 * time.Second
	}
	select {
	case response := <-c.responseCh:
		if active {
			return openAESGCM(key, response)
		}
		return response, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("timeout waiting for response")
	}
}

// Ping sends a lightweight test message to verify connection health.
// Used by ConnectionManager for keepalive monitoring.
func (c *Client) Ping() error {
	// Send REQUEST_IDENTITIES as a keepalive ping
	_, err := c.SendMessage([]byte{11})
	return err
}

// Disconnect closes the BLE connection.
func (c *Client) Disconnect() {
	if c == nil {
		return
	}
	
	c.mu.Lock()
	defer c.mu.Unlock()
	
	// Only stop the scan if this client started it. Calling StopScan on the
	// shared adapter while another client is scanning would kill that client's
	// reconnect attempt.
	if c.scanning && c.adapter != nil {
		c.adapter.StopScan()
		c.scanning = false
	}
	
	// Disconnect device if connected
	if c.connected {
		c.device.Disconnect()
		c.connected = false
	}

	// Clear session key so a reconnect starts a fresh ECDH exchange
	c.sessionActive = false
	c.sessionKey = [32]byte{}
}

// deriveSessionKey produces a 32-byte AES-256 key from an X25519 shared secret
// using HKDF-SHA256 (RFC 5869).  The nonce from the auth handshake is the salt
// so the derived key is bound to this specific session.
func deriveSessionKey(sharedSecret, salt []byte) [32]byte {
	// HKDF-Extract: PRK = HMAC-SHA256(salt, IKM)
	prk := hmac.New(sha256.New, salt)
	prk.Write(sharedSecret)
	extracted := prk.Sum(nil)

	// HKDF-Expand: OKM = HMAC-SHA256(PRK, info || 0x01)  (single 32-byte block)
	okm := hmac.New(sha256.New, extracted)
	okm.Write([]byte("pocket-ssh-session-v1\x01"))
	var key [32]byte
	copy(key[:], okm.Sum(nil))
	return key
}

// sealAESGCM encrypts plaintext with AES-256-GCM.
// Output layout: [12B nonce][ciphertext][16B auth tag]
func sealAESGCM(key [32]byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize()) // 12 bytes
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	// Seal prepends nonce then appends ciphertext+tag
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// openAESGCM decrypts an AES-256-GCM ciphertext produced by sealAESGCM.
func openAESGCM(key [32]byte, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize+gcm.Overhead() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	return gcm.Open(nil, data[:nonceSize], data[nonceSize:], nil)
}

func (c *Client) handleNotification(buf []byte) {
	log.Printf("BLE: *** handleNotification CALLED with %d bytes ***", len(buf))
	c.rxMu.Lock()
	defer c.rxMu.Unlock()

	c.rxBuf = append(c.rxBuf, buf...)
	log.Printf("BLE: rxBuf now has %d bytes (expected payload=%d)", len(c.rxBuf), c.rxExpected)

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

	// Complete response received.
	// Frame layout: [4B ble_len][4B corr_id][4B ssh_len][ssh_payload]
	// After stripping ble_len: fullPayload = [4B corr_id][4B ssh_len][ssh_payload]
	fullPayload := c.rxBuf[4:totalNeeded]

	// Reset before any early return so the next response can be received.
	c.rxBuf = nil
	c.rxExpected = 0

	if len(fullPayload) < 8 {
		log.Printf("BLE: response too short (%d bytes), dropping", len(fullPayload))
		return
	}

	// Drop responses whose correlation ID doesn't match — they belong to
	// another process sharing the same BLE connection/notifications.
	if !bytes.Equal(fullPayload[:4], c.pendingCorrID[:]) {
		log.Printf("BLE: correlation ID mismatch — dropping response (belongs to another client)")
		return
	}

	// Strip corr_id (4B) and inner ssh_len (4B) to get the raw SSH response.
	message := make([]byte, len(fullPayload)-8)
	copy(message, fullPayload[8:])

	log.Printf("BLE: received response (%d bytes, type=%d)", len(message), message[0])

	// Send to waiting caller
	select {
	case c.responseCh <- message:
	default:
		log.Println("Warning: response dropped (no receiver)")
	}
}
