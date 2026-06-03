package pkcs11

import (
	"encoding/binary"
	"fmt"
	"log"
)

// FindObjectsInit starts object enumeration
func (b *Backend) FindObjectsInit(sessionHandle uint64, class uint64) error {
	log.Printf("[PKCS11] FindObjectsInit: session=%d class=0x%x", sessionHandle, class)
	
	b.mu.Lock()
	defer b.mu.Unlock()

	session, exists := b.sessions[sessionHandle]
	if !exists {
		log.Printf("[PKCS11] Invalid session: %d", sessionHandle)
		return fmt.Errorf("invalid session")
	}

	if session.FindActive {
		log.Println("[PKCS11] Find operation already active")
		return fmt.Errorf("find operation already active")
	}

	// Load keys from Android if not done yet
	if len(b.objects) == 0 {
		log.Println("[PKCS11] No objects cached, loading from Android...")
		b.mu.Unlock()
		if err := b.LoadKeys(); err != nil {
			b.mu.Lock()
			log.Printf("[PKCS11] Failed to load keys: %v", err)
			return err
		}
		b.mu.Lock()
	}

	// Filter objects by class (0 = all objects)
	session.FindKeys = []uint64{}
	for handle, obj := range b.objects {
		if class == 0 || obj.Class == class {
			session.FindKeys = append(session.FindKeys, handle)
		}
	}

	session.FindActive = true
	log.Printf("[PKCS11] Find initialized: %d object(s) match", len(session.FindKeys))
	return nil
}

// FindObjects returns object handles
func (b *Backend) FindObjects(sessionHandle uint64, maxCount int) ([]uint64, error) {
	log.Printf("[PKCS11] FindObjects: session=%d maxCount=%d", sessionHandle, maxCount)
	
	b.mu.Lock()
	defer b.mu.Unlock()

	session, exists := b.sessions[sessionHandle]
	if !exists {
		log.Printf("[PKCS11] Invalid session: %d", sessionHandle)
		return nil, fmt.Errorf("invalid session")
	}

	if !session.FindActive {
		log.Println("[PKCS11] No find operation active")
		return nil, fmt.Errorf("no find operation active")
	}

	count := maxCount
	if count > len(session.FindKeys) {
		count = len(session.FindKeys)
	}

	handles := session.FindKeys[:count]
	session.FindKeys = session.FindKeys[count:]

	log.Printf("[PKCS11] Returning %d object(s), %d remaining", len(handles), len(session.FindKeys))
	return handles, nil
}

// FindObjectsFinal ends object enumeration
func (b *Backend) FindObjectsFinal(sessionHandle uint64) error {
	log.Printf("[PKCS11] FindObjectsFinal: session=%d", sessionHandle)
	
	b.mu.Lock()
	defer b.mu.Unlock()

	session, exists := b.sessions[sessionHandle]
	if !exists {
		log.Printf("[PKCS11] Invalid session: %d", sessionHandle)
		return fmt.Errorf("invalid session")
	}

	session.FindActive = false
	session.FindKeys = nil
	
	log.Println("[PKCS11] Find operation finalized")
	return nil
}

// GetAttributeValue retrieves object attributes
func (b *Backend) GetAttributeValue(objectHandle uint64, attrType uint64) ([]byte, error) {
	log.Printf("[PKCS11] GetAttributeValue: object=%d attr=0x%x", objectHandle, attrType)
	
	b.mu.RLock()
	defer b.mu.RUnlock()

	obj, exists := b.objects[objectHandle]
	if !exists {
		log.Printf("[PKCS11] Invalid object handle: %d", objectHandle)
		return nil, fmt.Errorf("invalid object handle")
	}

	switch attrType {
	case CKA_CLASS:
		val := make([]byte, 8)
		binary.LittleEndian.PutUint64(val, obj.Class)
		log.Printf("[PKCS11] Returning CLASS: %d", obj.Class)
		return val, nil

	case CKA_KEY_TYPE:
		val := make([]byte, 8)
		binary.LittleEndian.PutUint64(val, obj.KeyType)
		log.Printf("[PKCS11] Returning KEY_TYPE: %d", obj.KeyType)
		return val, nil

	case CKA_LABEL:
		log.Printf("[PKCS11] Returning LABEL: %q", obj.Label)
		return []byte(obj.Label), nil

	case CKA_ID:
		log.Printf("[PKCS11] Returning ID: %x", obj.ID)
		return obj.ID, nil

	case CKA_EC_PARAMS:
		if obj.KeyType == CKK_EC {
			// P-256 named curve OID (1.2.840.10045.3.1.7): 06 08 2a 86 48 ce 3d 03 01 07
			log.Println("[PKCS11] Returning EC_PARAMS: P-256 OID")
			return []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}, nil
		}
		// Ed25519 OID (1.3.101.112): 06 03 2b 65 70
		log.Println("[PKCS11] Returning EC_PARAMS: Ed25519 OID")
		return []byte{0x06, 0x03, 0x2b, 0x65, 0x70}, nil

	case CKA_EC_POINT:
		if obj.Class == CKO_PUBLIC_KEY {
			// DER OCTET STRING wrapping the EC point: 04 <len> <point>
			point := make([]byte, 2+len(obj.PublicKey))
			point[0] = 0x04
			point[1] = byte(len(obj.PublicKey))
			copy(point[2:], obj.PublicKey)
			log.Printf("[PKCS11] Returning EC_POINT: len=%d", len(point))
			return point, nil
		}
		log.Println("[PKCS11] Attribute not readable on private key")
		return nil, fmt.Errorf("attribute not readable on private key")

	case CKA_VALUE:
		if obj.Class == CKO_PUBLIC_KEY {
			log.Printf("[PKCS11] Returning public key: len=%d", len(obj.PublicKey))
			return obj.PublicKey, nil
		}
		log.Println("[PKCS11] Attribute not readable on private key")
		return nil, fmt.Errorf("attribute not readable on private key")

	case CKA_SIGN:
		log.Println("[PKCS11] Returning SIGN: TRUE")
		return []byte{1}, nil // TRUE

	case CKA_TOKEN:
		log.Println("[PKCS11] Returning TOKEN: TRUE")
		return []byte{1}, nil // TRUE (token object)

	case CKA_PRIVATE:
		if obj.Class == CKO_PRIVATE_KEY {
			log.Println("[PKCS11] Returning PRIVATE: TRUE")
			return []byte{1}, nil
		}
		log.Println("[PKCS11] Returning PRIVATE: FALSE")
		return []byte{0}, nil

	case CKA_SENSITIVE:
		if obj.Class == CKO_PRIVATE_KEY {
			log.Println("[PKCS11] Returning SENSITIVE: TRUE")
			return []byte{1}, nil
		}
		log.Println("[PKCS11] Returning SENSITIVE: FALSE")
		return []byte{0}, nil

	case CKA_EXTRACTABLE:
		log.Println("[PKCS11] Returning EXTRACTABLE: FALSE")
		return []byte{0}, nil // Never extractable

	default:
		log.Printf("[PKCS11] Attribute not supported: 0x%x", attrType)
		return nil, fmt.Errorf("attribute not supported")
	}
}

// SignInit initializes a signing operation
func (b *Backend) SignInit(sessionHandle uint64, mechanism uint64, keyHandle uint64) error {
	log.Printf("[PKCS11] SignInit: session=%d mechanism=0x%x key=%d", sessionHandle, mechanism, keyHandle)
	
	b.mu.Lock()
	defer b.mu.Unlock()

	session, exists := b.sessions[sessionHandle]
	if !exists {
		log.Printf("[PKCS11] Invalid session: %d", sessionHandle)
		return fmt.Errorf("invalid session")
	}

	obj, exists := b.objects[keyHandle]
	if !exists || obj.Class != CKO_PRIVATE_KEY {
		log.Printf("[PKCS11] Invalid private key: %d", keyHandle)
		return fmt.Errorf("invalid private key")
	}

	isEdDSA := obj.KeyType == CKK_EC_EDWARDS && mechanism == CKM_EDDSA
	isECDSA := obj.KeyType == CKK_EC && (mechanism == CKM_ECDSA || mechanism == CKM_ECDSA_SHA256)
	if !isEdDSA && !isECDSA {
		log.Printf("[PKCS11] Unsupported mechanism 0x%x for key type %d", mechanism, obj.KeyType)
		return fmt.Errorf("unsupported mechanism")
	}

	// Store the key handle for the sign operation
	session.SignKeyHandle = keyHandle
	
	log.Printf("[PKCS11] Sign operation initialized with key=%d", keyHandle)
	return nil
}
