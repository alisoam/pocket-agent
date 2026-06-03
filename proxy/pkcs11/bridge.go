package main

/*
#include <stdlib.h>
#include <string.h>

typedef unsigned char CK_BYTE;
typedef unsigned long CK_ULONG;
typedef unsigned long CK_RV;
typedef unsigned long CK_SESSION_HANDLE;
typedef unsigned long CK_OBJECT_HANDLE;
typedef unsigned long CK_SLOT_ID;
typedef unsigned long CK_FLAGS;
typedef unsigned long CK_USER_TYPE;
typedef void* CK_VOID_PTR;

typedef struct CK_ATTRIBUTE {
    unsigned long attrType;
    void* pValue;
    unsigned long ulValueLen;
} CK_ATTRIBUTE;

#define CKR_OK 0x00000000
#define CKR_FUNCTION_FAILED 0x00000006
#define CKR_ARGUMENTS_BAD 0x00000007
#define CKR_BUFFER_TOO_SMALL 0x00000150
#define CKR_CRYPTOKI_NOT_INITIALIZED 0x00000190
*/
import "C"
import (
	"crypto/ed25519"
	"log"
	"os"
	"path/filepath"
	"unsafe"

	"github.com/example/pocket-agent-proxy/internal/pairing"
	"github.com/example/pocket-agent-proxy/internal/pkcs11"
)

// loadPrivateKey loads the device's private key for BLE authentication
func loadPrivateKey() (ed25519.PrivateKey, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	configDir := filepath.Join(home, ".config", "pocket-agent")
	keysDir := filepath.Join(configDir, "keys")

	keys, err := pairing.LoadOrGenerateKeys(keysDir)
	if err != nil {
		return nil, err
	}

	return keys.PrivateKey, nil
}

//export GoInitialize
func GoInitialize() C.CK_RV {
	log.Println("[CGO] C_Initialize called")

	privateKey, err := loadPrivateKey()
	if err != nil {
		log.Printf("[CGO] Failed to load private key: %v", err)
		return C.CK_RV(pkcs11.CKR_FUNCTION_FAILED)
	}

	if err := pkcs11.Initialize(privateKey); err != nil {
		log.Printf("[CGO] Initialize failed: %v", err)
		return C.CK_RV(pkcs11.CKR_FUNCTION_FAILED)
	}

	log.Println("[CGO] C_Initialize succeeded")
	return C.CKR_OK
}

//export GoFinalize
func GoFinalize() C.CK_RV {
	log.Println("[CGO] C_Finalize called")
	pkcs11.Finalize()
	log.Println("[CGO] C_Finalize completed")
	return C.CKR_OK
}

//export GoOpenSession
func GoOpenSession(slotID C.CK_SLOT_ID, flags C.CK_FLAGS, phSession *C.CK_SESSION_HANDLE) C.CK_RV {
	log.Printf("[CGO] C_OpenSession called: slotID=%d flags=0x%x", slotID, flags)

	backend := pkcs11.GetBackend()
	if backend == nil {
		log.Println("[CGO] Backend not initialized")
		return C.CK_RV(pkcs11.CKR_CRYPTOKI_NOT_INITIALIZED)
	}

	handle, err := backend.OpenSession(uint64(slotID), uint64(flags))
	if err != nil {
		log.Printf("[CGO] OpenSession failed: %v", err)
		return C.CK_RV(pkcs11.CKR_FUNCTION_FAILED)
	}

	*phSession = C.CK_SESSION_HANDLE(handle)
	log.Printf("[CGO] C_OpenSession succeeded: session=%d", handle)
	return C.CKR_OK
}

//export GoCloseSession
func GoCloseSession(hSession C.CK_SESSION_HANDLE) C.CK_RV {
	log.Printf("[CGO] C_CloseSession called: session=%d", hSession)

	backend := pkcs11.GetBackend()
	if backend == nil {
		return C.CK_RV(pkcs11.CKR_CRYPTOKI_NOT_INITIALIZED)
	}

	if err := backend.CloseSession(uint64(hSession)); err != nil {
		log.Printf("[CGO] CloseSession failed: %v", err)
		return C.CK_RV(pkcs11.CKR_FUNCTION_FAILED)
	}

	log.Println("[CGO] C_CloseSession succeeded")
	return C.CKR_OK
}

//export GoLogin
func GoLogin(hSession C.CK_SESSION_HANDLE, userType C.CK_USER_TYPE) C.CK_RV {
	log.Printf("[CGO] C_Login called: session=%d userType=%d", hSession, userType)

	backend := pkcs11.GetBackend()
	if backend == nil {
		return C.CK_RV(pkcs11.CKR_CRYPTOKI_NOT_INITIALIZED)
	}

	if err := backend.Login(uint64(hSession), uint64(userType)); err != nil {
		log.Printf("[CGO] Login failed: %v", err)
		return C.CK_RV(pkcs11.CKR_FUNCTION_FAILED)
	}

	log.Println("[CGO] C_Login succeeded")
	return C.CKR_OK
}

//export GoLogout
func GoLogout(hSession C.CK_SESSION_HANDLE) C.CK_RV {
	log.Printf("[CGO] C_Logout called: session=%d", hSession)

	backend := pkcs11.GetBackend()
	if backend == nil {
		return C.CK_RV(pkcs11.CKR_CRYPTOKI_NOT_INITIALIZED)
	}

	if err := backend.Logout(uint64(hSession)); err != nil {
		log.Printf("[CGO] Logout failed: %v", err)
		return C.CK_RV(pkcs11.CKR_FUNCTION_FAILED)
	}

	log.Println("[CGO] C_Logout succeeded")
	return C.CKR_OK
}

//export GoFindObjectsInit
func GoFindObjectsInit(hSession C.CK_SESSION_HANDLE, pTemplate *C.CK_ATTRIBUTE, ulCount C.CK_ULONG) C.CK_RV {
	log.Printf("[CGO] C_FindObjectsInit called: session=%d count=%d", hSession, ulCount)

	backend := pkcs11.GetBackend()
	if backend == nil {
		return C.CK_RV(pkcs11.CKR_CRYPTOKI_NOT_INITIALIZED)
	}

	// Parse template to find CKA_CLASS filter
	var class uint64 = 0
	if ulCount > 0 && pTemplate != nil {
		// Convert C array to Go slice
		templateSlice := unsafe.Slice(pTemplate, ulCount)
		for i := 0; i < int(ulCount); i++ {
			attr := &templateSlice[i]
			if C.CK_ULONG(attr.attrType) == C.CK_ULONG(pkcs11.CKA_CLASS) && attr.pValue != nil {
				class = uint64(*(*C.CK_ULONG)(attr.pValue))
				log.Printf("[CGO] Filter by CLASS: %d", class)
			}
		}
	}

	if err := backend.FindObjectsInit(uint64(hSession), class); err != nil {
		log.Printf("[CGO] FindObjectsInit failed: %v", err)
		return C.CK_RV(pkcs11.CKR_FUNCTION_FAILED)
	}

	log.Println("[CGO] C_FindObjectsInit succeeded")
	return C.CKR_OK
}

//export GoFindObjects
func GoFindObjects(hSession C.CK_SESSION_HANDLE, phObject *C.CK_OBJECT_HANDLE, ulMaxObjectCount C.CK_ULONG, pulObjectCount *C.CK_ULONG) C.CK_RV {
	log.Printf("[CGO] C_FindObjects called: session=%d maxCount=%d", hSession, ulMaxObjectCount)

	backend := pkcs11.GetBackend()
	if backend == nil {
		return C.CK_RV(pkcs11.CKR_CRYPTOKI_NOT_INITIALIZED)
	}

	handles, err := backend.FindObjects(uint64(hSession), int(ulMaxObjectCount))
	if err != nil {
		log.Printf("[CGO] FindObjects failed: %v", err)
		return C.CK_RV(pkcs11.CKR_FUNCTION_FAILED)
	}

	// Copy handles to output array
	if phObject != nil {
		objects := (*[1 << 30]C.CK_OBJECT_HANDLE)(unsafe.Pointer(phObject))[:ulMaxObjectCount:ulMaxObjectCount]
		for i, h := range handles {
			objects[i] = C.CK_OBJECT_HANDLE(h)
		}
	}

	*pulObjectCount = C.CK_ULONG(len(handles))
	log.Printf("[CGO] C_FindObjects succeeded: found=%d", len(handles))
	return C.CKR_OK
}

//export GoFindObjectsFinal
func GoFindObjectsFinal(hSession C.CK_SESSION_HANDLE) C.CK_RV {
	log.Printf("[CGO] C_FindObjectsFinal called: session=%d", hSession)

	backend := pkcs11.GetBackend()
	if backend == nil {
		return C.CK_RV(pkcs11.CKR_CRYPTOKI_NOT_INITIALIZED)
	}

	if err := backend.FindObjectsFinal(uint64(hSession)); err != nil {
		log.Printf("[CGO] FindObjectsFinal failed: %v", err)
		return C.CK_RV(pkcs11.CKR_FUNCTION_FAILED)
	}

	log.Println("[CGO] C_FindObjectsFinal succeeded")
	return C.CKR_OK
}

//export GoGetAttributeValue
func GoGetAttributeValue(hSession C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE, pTemplate *C.CK_ATTRIBUTE, ulCount C.CK_ULONG) C.CK_RV {
	log.Printf("[CGO] C_GetAttributeValue called: session=%d object=%d count=%d", hSession, hObject, ulCount)

	backend := pkcs11.GetBackend()
	if backend == nil {
		return C.CK_RV(pkcs11.CKR_CRYPTOKI_NOT_INITIALIZED)
	}

	// Convert C array to Go slice
	templateSlice := unsafe.Slice(pTemplate, ulCount)

	for i := 0; i < int(ulCount); i++ {
		attr := &templateSlice[i]
		attrType := uint64(attr.attrType)

		value, err := backend.GetAttributeValue(uint64(hObject), attrType)
		if err != nil {
			log.Printf("[CGO] GetAttributeValue failed for attr 0x%x: %v", attrType, err)
			attr.ulValueLen = C.CK_ULONG(0xFFFFFFFF) // CK_UNAVAILABLE_INFORMATION
			continue
		}

		if attr.pValue == nil {
			// Query length only
			attr.ulValueLen = C.CK_ULONG(len(value))
		} else {
			// Copy value
			if uint64(attr.ulValueLen) < uint64(len(value)) {
				attr.ulValueLen = C.CK_ULONG(len(value))
				return C.CKR_BUFFER_TOO_SMALL
			}

			C.memcpy(attr.pValue, unsafe.Pointer(&value[0]), C.size_t(len(value)))
			attr.ulValueLen = C.CK_ULONG(len(value))
		}
	}

	log.Println("[CGO] C_GetAttributeValue succeeded")
	return C.CKR_OK
}

//export GoSignInit
func GoSignInit(hSession C.CK_SESSION_HANDLE, mechanism C.CK_ULONG, hKey C.CK_OBJECT_HANDLE) C.CK_RV {
	log.Printf("[CGO] C_SignInit called: session=%d mechanism=0x%x key=%d", hSession, mechanism, hKey)

	backend := pkcs11.GetBackend()
	if backend == nil {
		return C.CK_RV(pkcs11.CKR_CRYPTOKI_NOT_INITIALIZED)
	}

	if err := backend.SignInit(uint64(hSession), uint64(mechanism), uint64(hKey)); err != nil {
		log.Printf("[CGO] SignInit failed: %v", err)
		return C.CK_RV(pkcs11.CKR_FUNCTION_FAILED)
	}

	log.Println("[CGO] C_SignInit succeeded")
	return C.CKR_OK
}

// cachedSignature holds the result of the length-query C_Sign call so the
// follow-up data-copy call doesn't trigger a second BLE round-trip to Android.
var cachedSignature []byte

//export GoSign
func GoSign(hSession C.CK_SESSION_HANDLE, hKey C.CK_OBJECT_HANDLE, pData *C.CK_BYTE, ulDataLen C.CK_ULONG, pSignature *C.CK_BYTE, pulSignatureLen *C.CK_ULONG) C.CK_RV {
	log.Printf("[CGO] C_Sign called: session=%d key=%d dataLen=%d sigBufNil=%v", hSession, hKey, ulDataLen, pSignature == nil)

	backend := pkcs11.GetBackend()
	if backend == nil {
		return C.CK_RV(pkcs11.CKR_CRYPTOKI_NOT_INITIALIZED)
	}

	data := C.GoBytes(unsafe.Pointer(pData), C.int(ulDataLen))

	if pSignature == nil {
		// Length query: perform the BLE sign now and cache the result.
		sig, err := backend.Sign(uint64(hSession), uint64(hKey), data)
		if err != nil {
			log.Printf("[CGO] C_Sign (query) failed: %v", err)
			cachedSignature = nil
			return C.CK_RV(pkcs11.CKR_FUNCTION_FAILED)
		}
		cachedSignature = sig
		*pulSignatureLen = C.CK_ULONG(len(sig))
		log.Printf("[CGO] C_Sign query: sigLen=%d (cached)", len(sig))
		return C.CKR_OK
	}

	// Data-copy call: use the cached signature if available, otherwise sign again.
	var signature []byte
	if cachedSignature != nil {
		signature = cachedSignature
		cachedSignature = nil
		log.Printf("[CGO] C_Sign: using cached signature len=%d", len(signature))
	} else {
		var err error
		signature, err = backend.Sign(uint64(hSession), uint64(hKey), data)
		if err != nil {
			log.Printf("[CGO] C_Sign failed: %v", err)
			return C.CK_RV(pkcs11.CKR_FUNCTION_FAILED)
		}
	}

	if uint64(*pulSignatureLen) < uint64(len(signature)) {
		*pulSignatureLen = C.CK_ULONG(len(signature))
		return C.CKR_BUFFER_TOO_SMALL
	}

	C.memcpy(unsafe.Pointer(pSignature), unsafe.Pointer(&signature[0]), C.size_t(len(signature)))
	*pulSignatureLen = C.CK_ULONG(len(signature))
	log.Printf("[CGO] C_Sign succeeded: sigLen=%d", len(signature))
	return C.CKR_OK
}

func main() {}
