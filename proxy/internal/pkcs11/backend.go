package pkcs11

import (
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/example/pocket-agent-proxy/internal/ble"
)

// Backend manages PKCS#11 state and BLE communication
type Backend struct {
	connMgr    *ble.ConnectionManager
	privateKey ed25519.PrivateKey
	
	connStarted bool // Track if BLE connection was actually started

	sessions   map[uint64]*Session
	objects    map[uint64]*Object
	nextHandle uint64

	mu sync.RWMutex
}

// Session represents a PKCS#11 session
type Session struct {
	Handle          uint64
	SlotID          uint64
	Flags           uint64
	State           uint64
	SignKeyHandle   uint64   // Active key for signing operation
	FindActive      bool
	FindKeys        []uint64 // Object handles from current find operation
	CachedSignature []byte   // Result of the length-query C_Sign; consumed by the follow-up data-copy call
}

// Object represents a key object
type Object struct {
	Handle    uint64
	Class     uint64 // CKO_PUBLIC_KEY or CKO_PRIVATE_KEY
	KeyType   uint64 // CKK_EC_EDWARDS or CKK_EC
	Label     string
	ID        []byte // SSH key fingerprint or Android alias
	PublicKey []byte // Raw key bytes: 32-byte Ed25519 OR 65-byte P-256 EC point
}

var globalBackend *Backend

// Initialize sets up the PKCS#11 backend
func Initialize(privateKey ed25519.PrivateKey) error {
	log.Println("[PKCS11] Initializing backend...")

	if globalBackend != nil {
		log.Println("[PKCS11] Already initialized, reusing existing backend")
		return nil
	}

	connMgr := ble.NewConnectionManager(privateKey)

	globalBackend = &Backend{
		connMgr:     connMgr,
		privateKey:  privateKey,
		connStarted: true,
		sessions:    make(map[uint64]*Session),
		objects:     make(map[uint64]*Object),
		nextHandle:  1,
	}

	// Start BLE connection manager immediately so it has time to connect
	// before C_FindObjectsInit is called.
	if err := connMgr.Start(); err != nil {
		globalBackend = nil
		return fmt.Errorf("failed to start BLE connection manager: %w", err)
	}

	log.Println("[PKCS11] Backend initialized, BLE connection manager started")
	return nil
}

// Finalize shuts down the backend
func Finalize() {
	log.Println("[PKCS11] Finalizing backend...")
	
	if globalBackend == nil {
		log.Println("[PKCS11] Not initialized, nothing to finalize")
		return
	}

	// Stop connection manager if it was started
	if globalBackend.connStarted && globalBackend.connMgr != nil {
		log.Println("[PKCS11] Stopping connection manager...")
		globalBackend.connMgr.Stop()
		log.Println("[PKCS11] Connection manager stopped")
	}
	
	globalBackend = nil
	
	log.Println("[PKCS11] Backend finalized")
}

// GetBackend returns the global backend instance
func GetBackend() *Backend {
	return globalBackend
}

// CacheSignature stores the signature from the length-query C_Sign call into
// the session so the follow-up data-copy call can reuse it without a second
// BLE round-trip. Keyed by session handle to prevent cross-session confusion.
func (b *Backend) CacheSignature(sessionHandle uint64, sig []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	session, exists := b.sessions[sessionHandle]
	if !exists {
		return fmt.Errorf("invalid session handle: %d", sessionHandle)
	}
	session.CachedSignature = sig
	return nil
}

// TakeCachedSignature retrieves and clears the cached signature for a session.
// Returns nil if no signature is cached.
func (b *Backend) TakeCachedSignature(sessionHandle uint64) []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	session, exists := b.sessions[sessionHandle]
	if !exists {
		return nil
	}
	sig := session.CachedSignature
	session.CachedSignature = nil
	return sig
}

// ensureConnected starts the BLE connection manager if not already started,
// then waits until actually connected (or timeout).
func (b *Backend) ensureConnected() error {
	b.mu.Lock()
	if !b.connStarted {
		log.Println("[PKCS11] Starting BLE connection manager...")
		if err := b.connMgr.Start(); err != nil {
			b.mu.Unlock()
			log.Printf("[PKCS11] Failed to start connection manager: %v", err)
			return fmt.Errorf("failed to start connection manager: %w", err)
		}
		b.connStarted = true
		log.Println("[PKCS11] BLE connection manager started")
	}
	b.mu.Unlock()

	if !b.connMgr.IsConnected() {
		log.Println("[PKCS11] Waiting for BLE connection to Android (open the app if not running)...")
		if err := b.connMgr.WaitUntilConnected(60 * time.Second); err != nil {
			return fmt.Errorf("BLE not ready: %w", err)
		}
	}
	return nil
}

// OpenSession creates a new session
func (b *Backend) OpenSession(slotID uint64, flags uint64) (uint64, error) {
	log.Printf("[PKCS11] OpenSession: slotID=%d flags=0x%x", slotID, flags)
	
	if slotID != 0 {
		log.Printf("[PKCS11] Invalid slot ID: %d", slotID)
		return 0, fmt.Errorf("invalid slot ID")
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	handle := b.nextHandle
	b.nextHandle++

	// Determine session state based on flags
	state := CKS_RO_PUBLIC_SESSION
	if flags&CKF_RW_SESSION != 0 {
		state = CKS_RW_PUBLIC_SESSION
	}

	b.sessions[handle] = &Session{
		Handle: handle,
		SlotID: slotID,
		Flags:  flags,
		State:  uint64(state),
	}

	log.Printf("[PKCS11] Session opened: handle=%d state=%d", handle, state)
	return handle, nil
}

// CloseSession closes a session
func (b *Backend) CloseSession(handle uint64) error {
	log.Printf("[PKCS11] CloseSession: handle=%d", handle)
	
	b.mu.Lock()
	defer b.mu.Unlock()

	if _, exists := b.sessions[handle]; !exists {
		log.Printf("[PKCS11] Invalid session handle: %d", handle)
		return fmt.Errorf("invalid session handle")
	}

	delete(b.sessions, handle)
	log.Printf("[PKCS11] Session closed: handle=%d", handle)
	return nil
}

// CloseAllSessions closes all sessions belonging to the given slot
func (b *Backend) CloseAllSessions(slotID uint64) error {
	log.Printf("[PKCS11] CloseAllSessions: slotID=%d", slotID)

	b.mu.Lock()
	defer b.mu.Unlock()

	for handle, session := range b.sessions {
		if session.SlotID == slotID {
			delete(b.sessions, handle)
			log.Printf("[PKCS11] Session closed via CloseAllSessions: handle=%d", handle)
		}
	}
	return nil
}

// Login authenticates the user
func (b *Backend) Login(sessionHandle uint64, userType uint64) error {
	log.Printf("[PKCS11] Login: session=%d userType=%d", sessionHandle, userType)
	
	b.mu.Lock()
	defer b.mu.Unlock()

	session, exists := b.sessions[sessionHandle]
	if !exists {
		log.Printf("[PKCS11] Invalid session handle: %d", sessionHandle)
		return fmt.Errorf("invalid session handle")
	}

	if userType != CKU_USER {
		log.Printf("[PKCS11] Invalid user type: %d", userType)
		return fmt.Errorf("invalid user type")
	}

	// Update session state to logged in
	if session.State == CKS_RO_PUBLIC_SESSION {
		session.State = uint64(CKS_RO_USER_FUNCTIONS)
	} else if session.State == CKS_RW_PUBLIC_SESSION {
		session.State = uint64(CKS_RW_USER_FUNCTIONS)
	}

	log.Printf("[PKCS11] User logged in: session=%d new_state=%d", sessionHandle, session.State)
	return nil
}

// Logout logs out the user
func (b *Backend) Logout(sessionHandle uint64) error {
	log.Printf("[PKCS11] Logout: session=%d", sessionHandle)
	
	b.mu.Lock()
	defer b.mu.Unlock()

	session, exists := b.sessions[sessionHandle]
	if !exists {
		log.Printf("[PKCS11] Invalid session handle: %d", sessionHandle)
		return fmt.Errorf("invalid session handle")
	}

	// Update session state to logged out
	if session.State == CKS_RO_USER_FUNCTIONS {
		session.State = uint64(CKS_RO_PUBLIC_SESSION)
	} else if session.State == CKS_RW_USER_FUNCTIONS {
		session.State = uint64(CKS_RW_PUBLIC_SESSION)
	}

	log.Printf("[PKCS11] User logged out: session=%d new_state=%d", sessionHandle, session.State)
	return nil
}

// LoadKeys fetches keys from Android via BLE (REQUEST_IDENTITIES)
func (b *Backend) LoadKeys() error {
	log.Println("[PKCS11] Loading keys from Android...")
	
	// Ensure BLE connection is started
	if err := b.ensureConnected(); err != nil {
		return err
	}
	
	// Send REQUEST_IDENTITIES (message type 11)
	response, err := b.connMgr.SendMessage([]byte{11})
	if err != nil {
		log.Printf("[PKCS11] Failed to list keys: %v", err)
		return fmt.Errorf("failed to list keys: %w", err)
	}

	if len(response) < 5 || response[0] != 12 {
		log.Printf("[PKCS11] Unexpected response from agent: type=%d len=%d", response[0], len(response))
		return fmt.Errorf("unexpected response from agent")
	}

	// Parse response: [type(1)][nkeys(4)][key1][key2]...
	nkeys := int(binary.BigEndian.Uint32(response[1:5]))
	log.Printf("[PKCS11] Agent reported %d key(s)", nkeys)
	offset := 5

	b.mu.Lock()
	defer b.mu.Unlock()

	// Clear existing objects
	b.objects = make(map[uint64]*Object)

	for i := 0; i < nkeys; i++ {
		// Parse SSH key blob: [len(4)][key_type_len(4)][key_type][pubkey_len(4)][pubkey]
		if offset+4 > len(response) {
			log.Printf("[PKCS11] Truncated response at key %d", i)
			break
		}

		blobLen := int(binary.BigEndian.Uint32(response[offset : offset+4]))
		offset += 4

		if offset+blobLen > len(response) {
			log.Printf("[PKCS11] Truncated key blob at key %d", i)
			break
		}

		keyBlob := response[offset : offset+blobLen]
		offset += blobLen

		// Parse comment (label)
		if offset+4 > len(response) {
			log.Printf("[PKCS11] Truncated comment at key %d", i)
			break
		}
		commentLen := int(binary.BigEndian.Uint32(response[offset : offset+4]))
		offset += 4

		comment := ""
		if offset+commentLen <= len(response) {
			comment = string(response[offset : offset+commentLen])
			offset += commentLen
		}

		log.Printf("[PKCS11] Key %d blob hex: %x", i, keyBlob)

		var pubKey []byte
		var keyType uint64

		if p := b.extractEd25519PublicKey(keyBlob); p != nil {
			pubKey = p
			keyType = CKK_EC_EDWARDS
			log.Printf("[PKCS11] Found Ed25519 key: label=%q", comment)
		} else if p := b.extractP256PublicKey(keyBlob); p != nil {
			pubKey = p
			keyType = CKK_EC
			log.Printf("[PKCS11] Found ECDSA P-256 key: label=%q", comment)
		} else {
			log.Printf("[PKCS11] Skipping unknown key type %d", i)
			continue
		}

		// Create public key object
		pubHandle := b.nextHandle
		b.nextHandle++
		b.objects[pubHandle] = &Object{
			Handle:    pubHandle,
			Class:     CKO_PUBLIC_KEY,
			KeyType:   keyType,
			Label:     comment,
			ID:        []byte(fmt.Sprintf("key-%d", i)),
			PublicKey: pubKey,
		}

		// Create corresponding private key object
		privHandle := b.nextHandle
		b.nextHandle++
		b.objects[privHandle] = &Object{
			Handle:    privHandle,
			Class:     CKO_PRIVATE_KEY,
			KeyType:   keyType,
			Label:     comment,
			ID:        []byte(fmt.Sprintf("key-%d", i)),
			PublicKey: pubKey,
		}

		log.Printf("[PKCS11] Created objects: public=%d private=%d (keyType=%d)", pubHandle, privHandle, keyType)
	}

	log.Printf("[PKCS11] Loaded %d object(s) total", len(b.objects))
	return nil
}

// extractP256PublicKey parses "ecdsa-sha2-nistp256" SSH blob → 65-byte EC point
func (b *Backend) extractP256PublicKey(blob []byte) []byte {
	if len(blob) < 4 {
		return nil
	}
	typeLen := int(binary.BigEndian.Uint32(blob[0:4]))
	if len(blob) < 4+typeLen+4 {
		return nil
	}
	if string(blob[4:4+typeLen]) != "ecdsa-sha2-nistp256" {
		return nil
	}
	offset := 4 + typeLen
	// skip curve name ("nistp256")
	curveLen := int(binary.BigEndian.Uint32(blob[offset : offset+4]))
	offset += 4 + curveLen
	if offset+4 > len(blob) {
		return nil
	}
	pointLen := int(binary.BigEndian.Uint32(blob[offset : offset+4]))
	offset += 4
	if len(blob) < offset+pointLen || pointLen != 65 || blob[offset] != 0x04 {
		return nil
	}
	return blob[offset : offset+65]
}

// extractEd25519PublicKey parses SSH wire format to extract raw 32-byte pubkey
func (b *Backend) extractEd25519PublicKey(blob []byte) []byte {
	// SSH format: [type_len(4)]["ssh-ed25519"][key_len(4)][32_bytes]
	if len(blob) < 4 {
		return nil
	}

	typeLen := int(binary.BigEndian.Uint32(blob[0:4]))
	if len(blob) < 4+typeLen+4 {
		return nil
	}

	keyType := string(blob[4 : 4+typeLen])
	if keyType != "ssh-ed25519" {
		return nil
	}

	offset := 4 + typeLen
	keyLen := int(binary.BigEndian.Uint32(blob[offset : offset+4]))
	offset += 4

	if keyLen != 32 || len(blob) < offset+32 {
		return nil
	}

	return blob[offset : offset+32]
}

// Sign performs Ed25519 signature via BLE (SIGN_REQUEST).
// When objectHandle is 0 the key handle is resolved from the session's SignKeyHandle,
// which was set by SignInit — this keeps key state per-session and out of C globals.
func (b *Backend) Sign(sessionHandle uint64, objectHandle uint64, data []byte) ([]byte, error) {
	log.Printf("[PKCS11] Sign: session=%d object=%d data_len=%d", sessionHandle, objectHandle, len(data))

	b.mu.RLock()
	session, sessionExists := b.sessions[sessionHandle]
	if sessionExists && objectHandle == 0 {
		objectHandle = session.SignKeyHandle
	}
	obj, objExists := b.objects[objectHandle]
	b.mu.RUnlock()

	if !sessionExists {
		log.Printf("[PKCS11] Invalid session handle: %d", sessionHandle)
		return nil, fmt.Errorf("invalid session handle")
	}

	if objectHandle == 0 {
		log.Printf("[PKCS11] Sign called without prior SignInit on session %d", sessionHandle)
		return nil, fmt.Errorf("sign operation not initialized")
	}

	if !objExists || obj.Class != CKO_PRIVATE_KEY {
		log.Printf("[PKCS11] Invalid private key handle: %d", objectHandle)
		return nil, fmt.Errorf("invalid private key handle")
	}

	log.Printf("[PKCS11] Signing with key: label=%q keyType=%d", obj.Label, obj.KeyType)

	// Build SIGN_REQUEST message (type 13)
	// Format: [type(1)][pubkey_blob_len(4)][pubkey_blob][data_len(4)][data][flags(4)]
	pubkeyBlob := b.buildSSHPublicKeyBlob(obj)

	msg := make([]byte, 1+4+len(pubkeyBlob)+4+len(data)+4)
	msg[0] = 13 // SIGN_REQUEST

	offset := 1
	binary.BigEndian.PutUint32(msg[offset:], uint32(len(pubkeyBlob)))
	offset += 4
	copy(msg[offset:], pubkeyBlob)
	offset += len(pubkeyBlob)

	binary.BigEndian.PutUint32(msg[offset:], uint32(len(data)))
	offset += 4
	copy(msg[offset:], data)
	offset += len(data)

	binary.BigEndian.PutUint32(msg[offset:], 0) // flags

	log.Println("[PKCS11] Sending sign request to Android (will trigger biometric)...")

	// Send to Android (triggers biometric)
	response, err := b.connMgr.SendMessage(msg)
	if err != nil {
		log.Printf("[PKCS11] Signing failed: %v", err)
		return nil, fmt.Errorf("signing failed: %w", err)
	}

	if len(response) < 1 || response[0] != 14 { // SSH_AGENT_SIGN_RESPONSE
		log.Printf("[PKCS11] Signing rejected or failed: response_type=%d", response[0])
		return nil, fmt.Errorf("signing rejected or failed")
	}

	// Parse signature blob
	if len(response) < 5 {
		log.Println("[PKCS11] Invalid signature response")
		return nil, fmt.Errorf("invalid signature response")
	}

	sigBlobLen := int(binary.BigEndian.Uint32(response[1:5]))
	if len(response) < 5+sigBlobLen {
		log.Println("[PKCS11] Truncated signature response")
		return nil, fmt.Errorf("truncated signature response")
	}

	sigBlob := response[5 : 5+sigBlobLen]
	log.Printf("[PKCS11] sigBlob (%d bytes) hex: %x", len(sigBlob), sigBlob)

	var rawSig []byte
	if obj.KeyType == CKK_EC {
		rawSig = b.extractP256Signature(sigBlob)
	} else {
		rawSig = b.extractEd25519Signature(sigBlob)
	}
	if rawSig == nil {
		log.Println("[PKCS11] Failed to parse signature")
		return nil, fmt.Errorf("failed to parse signature")
	}

	log.Printf("[PKCS11] Signature successful: sig_len=%d", len(rawSig))
	return rawSig, nil
}

// buildSSHPublicKeyBlob creates SSH wire format public key blob for SIGN_REQUEST.
func (b *Backend) buildSSHPublicKeyBlob(obj *Object) []byte {
	encStr := func(s string) []byte {
		buf := make([]byte, 4+len(s))
		binary.BigEndian.PutUint32(buf, uint32(len(s)))
		copy(buf[4:], s)
		return buf
	}
	encBytes := func(d []byte) []byte {
		buf := make([]byte, 4+len(d))
		binary.BigEndian.PutUint32(buf, uint32(len(d)))
		copy(buf[4:], d)
		return buf
	}

	if obj.KeyType == CKK_EC_EDWARDS {
		return append(encStr("ssh-ed25519"), encBytes(obj.PublicKey)...)
	}
	// P-256: "ecdsa-sha2-nistp256" | "nistp256" | <65-byte EC point>
	return append(append(encStr("ecdsa-sha2-nistp256"), encStr("nistp256")...), encBytes(obj.PublicKey)...)
}

// extractP256Signature parses an SSH ECDSA P-256 signature blob and returns
// raw 64-byte r||s suitable for PKCS#11 CKM_ECDSA.
// SSH format: string "ecdsa-sha2-nistp256" | string (mpint r || mpint s)
func (b *Backend) extractP256Signature(blob []byte) []byte {
	if len(blob) < 4 {
		return nil
	}
	typeLen := int(binary.BigEndian.Uint32(blob[0:4]))
	if len(blob) < 4+typeLen+4 {
		return nil
	}
	if string(blob[4:4+typeLen]) != "ecdsa-sha2-nistp256" {
		log.Printf("[PKCS11] P-256 sig: unexpected type %q", string(blob[4:4+typeLen]))
		return nil
	}
	offset := 4 + typeLen
	innerLen := int(binary.BigEndian.Uint32(blob[offset : offset+4]))
	offset += 4
	if len(blob) < offset+innerLen {
		return nil
	}
	inner := blob[offset : offset+innerLen]

	// Parse mpint r and mpint s from inner
	extractMpint := func(pos int) ([]byte, int) {
		if pos+4 > len(inner) {
			return nil, pos
		}
		n := int(binary.BigEndian.Uint32(inner[pos : pos+4]))
		pos += 4
		if pos+n > len(inner) {
			return nil, pos
		}
		v := inner[pos : pos+n]
		pos += n
		// strip leading 0x00 sign byte(s)
		for len(v) > 1 && v[0] == 0x00 {
			v = v[1:]
		}
		return v, pos
	}

	r, pos := extractMpint(0)
	s, _ := extractMpint(pos)
	if r == nil || s == nil || len(r) > 32 || len(s) > 32 {
		log.Printf("[PKCS11] P-256 sig: bad r/s (r=%d s=%d)", len(r), len(s))
		return nil
	}

	result := make([]byte, 64)
	copy(result[32-len(r):32], r)
	copy(result[64-len(s):64], s)
	log.Printf("[PKCS11] P-256 sig: raw 64 bytes r||s extracted")
	return result
}

// extractEd25519Signature parses SSH signature format to raw 64 bytes.
// Also handles DER-wrapped signatures (some Android Keystore implementations
// wrap the Ed25519 R+S bytes in a DER SEQUENCE).
func (b *Backend) extractEd25519Signature(blob []byte) []byte {
	if len(blob) < 4 {
		return nil
	}

	typeLen := int(binary.BigEndian.Uint32(blob[0:4]))
	if len(blob) < 4+typeLen+4 {
		return nil
	}

	offset := 4 + typeLen
	sigLen := int(binary.BigEndian.Uint32(blob[offset : offset+4]))
	offset += 4

	if len(blob) < offset+sigLen {
		return nil
	}

	sigBytes := blob[offset : offset+sigLen]

	if sigLen == 64 {
		return sigBytes
	}

	// Try DER-decode: SEQUENCE { INTEGER r, INTEGER s } → raw 64-byte R||S
	if sigLen > 4 && sigBytes[0] == 0x30 {
		raw := derDecodeSignature(sigBytes)
		if raw != nil {
			log.Printf("[PKCS11] DER-decoded signature to raw 64 bytes")
			return raw
		}
	}

	log.Printf("[PKCS11] Unexpected signature length %d, first bytes: %x", sigLen, sigBytes[:min(8, len(sigBytes))])
	return nil
}

// derDecodeSignature decodes a DER SEQUENCE { INTEGER r, INTEGER s } into
// a raw 64-byte R||S signature (used by some Android Keystore implementations).
func derDecodeSignature(der []byte) []byte {
	if len(der) < 6 || der[0] != 0x30 {
		return nil
	}
	pos := 2 // skip SEQUENCE tag + length

	extract := func() ([]byte, bool) {
		if pos+2 > len(der) || der[pos] != 0x02 {
			return nil, false
		}
		pos++ // skip INTEGER tag
		n := int(der[pos])
		pos++
		if pos+n > len(der) {
			return nil, false
		}
		v := der[pos : pos+n]
		pos += n
		if len(v) > 0 && v[0] == 0x00 {
			v = v[1:] // strip leading zero padding
		}
		return v, true
	}

	r, ok := extract()
	if !ok || len(r) > 32 {
		return nil
	}
	s, ok := extract()
	if !ok || len(s) > 32 {
		return nil
	}

	result := make([]byte, 64)
	copy(result[32-len(r):32], r)
	copy(result[64-len(s):64], s)
	return result
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
