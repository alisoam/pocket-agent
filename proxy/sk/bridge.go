package main

/*
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Struct definitions matching the sk-api.h ABI (OpenSSH 10 / version 0x000a0000).
// We define them here rather than #include "sk-api.h" to avoid a conflict
// between the const-qualified forward declarations in that header and the
// non-const declarations cgo auto-generates for //export functions.

struct sk_enroll_response {
	uint8_t  flags;
	uint8_t *public_key;
	size_t   public_key_len;
	uint8_t *key_handle;
	size_t   key_handle_len;
	uint8_t *signature;
	size_t   signature_len;
	uint8_t *attestation_cert;
	size_t   attestation_cert_len;
	uint8_t *authdata;
	size_t   authdata_len;
};

struct sk_sign_response {
	uint8_t  flags;
	uint32_t counter;
	uint8_t *sig_r;
	size_t   sig_r_len;
	uint8_t *sig_s;
	size_t   sig_s_len;
};

struct sk_resident_key {
	uint32_t  alg;
	size_t    slot;
	char     *application;
	void     *key; // struct sshkey * — opaque, never populated
	uint8_t   flags;
	uint8_t  *user_id;
	size_t    user_id_len;
};

struct sk_option {
	char    *name;
	char    *value;
	uint8_t  required;
};

#define SSH_SK_ERR_GENERAL          -1
#define SSH_SK_ERR_UNSUPPORTED      -2
#define SSH_SK_ERR_PIN_REQUIRED     -3
#define SSH_SK_ERR_DEVICE_NOT_FOUND -4
*/
import "C"
import (
	"crypto/ed25519"
	"log"
	"os"
	"path/filepath"
	"unsafe"

	"github.com/example/pocket-agent-proxy/internal/pairing"
)

func loadPrivateKey() (ed25519.PrivateKey, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	keysDir := filepath.Join(home, ".config", "pocket-agent", "keys")
	keys, err := pairing.LoadOrGenerateKeys(keysDir)
	if err != nil {
		return nil, err
	}
	return keys.PrivateKey, nil
}

func ensureBackend() *SKBackend {
	backend := getSKBackend()
	if backend != nil {
		return backend
	}
	privateKey, err := loadPrivateKey()
	if err != nil {
		log.Printf("[SK] Failed to load private key: %v", err)
		return nil
	}
	if err := initSK(privateKey); err != nil {
		log.Printf("[SK] Failed to initialize backend: %v", err)
		return nil
	}
	return getSKBackend()
}

//export sk_api_version
func sk_api_version() C.uint32_t {
	return C.uint32_t(0x000a0000)
}

//export sk_enroll
func sk_enroll(
	alg C.uint32_t,
	challenge *C.uint8_t,
	challengeLen C.size_t,
	application *C.char,
	flags C.uint8_t,
	pin *C.char,
	options **C.struct_sk_option,
	enrollResponse **C.struct_sk_enroll_response,
) C.int {
	// Suppress unused-parameter warnings; we don't use challenge, pin, or options.
	_ = challenge
	_ = challengeLen
	_ = pin
	_ = options

	log.Printf("[SK] sk_enroll: alg=%d flags=0x%02x", alg, flags)

	if uint32(alg) != 0 && uint32(alg) != 1 { // SSH_SK_ECDSA or SSH_SK_ED25519
		log.Printf("[SK] sk_enroll: unsupported algorithm %d", alg)
		return C.int(C.SSH_SK_ERR_UNSUPPORTED)
	}

	backend := ensureBackend()
	if backend == nil {
		return C.int(C.SSH_SK_ERR_GENERAL)
	}

	app := C.GoString(application)
	label := optionValue(options, "label")
	pubkey, keyHandle, actualAlg, err := backend.Enroll(app, uint32(alg), byte(flags), label)
	if err != nil {
		log.Printf("[SK] sk_enroll: %v", err)
		if uint32(alg) == 1 {
			log.Printf("[SK] Hint: your device may not support ed25519-sk — try: ssh-keygen -t ecdsa-sk -w <lib>")
		}
		return C.int(C.SSH_SK_ERR_GENERAL)
	}
	if actualAlg != uint32(alg) {
		// Should not happen — Android deletes and fails on mismatch, but guard anyway.
		log.Printf("[SK] sk_enroll: alg mismatch (requested %d, got %d) — treating as unsupported", alg, actualAlg)
		return C.int(C.SSH_SK_ERR_UNSUPPORTED)
	}

	resp := (*C.struct_sk_enroll_response)(C.calloc(1, C.size_t(C.sizeof_struct_sk_enroll_response)))
	if resp == nil {
		return C.int(C.SSH_SK_ERR_GENERAL)
	}

	resp.flags = flags // propagate user-presence/UV flags from the request

	resp.public_key = (*C.uint8_t)(C.malloc(C.size_t(len(pubkey))))
	if resp.public_key == nil {
		C.free(unsafe.Pointer(resp))
		return C.int(C.SSH_SK_ERR_GENERAL)
	}
	resp.public_key_len = C.size_t(len(pubkey))
	C.memcpy(unsafe.Pointer(resp.public_key), unsafe.Pointer(&pubkey[0]), C.size_t(len(pubkey)))

	resp.key_handle = (*C.uint8_t)(C.malloc(C.size_t(len(keyHandle))))
	if resp.key_handle == nil {
		C.free(unsafe.Pointer(resp.public_key))
		C.free(unsafe.Pointer(resp))
		return C.int(C.SSH_SK_ERR_GENERAL)
	}
	resp.key_handle_len = C.size_t(len(keyHandle))
	C.memcpy(unsafe.Pointer(resp.key_handle), unsafe.Pointer(&keyHandle[0]), C.size_t(len(keyHandle)))

	// No attestation certificate — not required for SSH user authentication.
	resp.signature = nil
	resp.signature_len = 0
	resp.attestation_cert = nil
	resp.attestation_cert_len = 0
	resp.authdata = nil
	resp.authdata_len = 0

	*enrollResponse = resp
	log.Printf("[SK] sk_enroll: success, handle=%q", string(keyHandle))
	return C.int(0)
}

//export sk_sign
func sk_sign(
	alg C.uint32_t,
	data *C.uint8_t,
	datalen C.size_t,
	application *C.char,
	keyHandle *C.uint8_t,
	keyHandleLen C.size_t,
	flags C.uint8_t,
	pin *C.char,
	options **C.struct_sk_option,
	signResponse **C.struct_sk_sign_response,
) C.int {
	_ = pin
	_ = options

	log.Printf("[SK] sk_sign: alg=%d datalen=%d flags=0x%02x", alg, datalen, flags)

	if uint32(alg) != 0 && uint32(alg) != 1 {
		log.Printf("[SK] sk_sign: unsupported algorithm %d", alg)
		return C.int(C.SSH_SK_ERR_UNSUPPORTED)
	}

	backend := ensureBackend()
	if backend == nil {
		return C.int(C.SSH_SK_ERR_GENERAL)
	}

	app := C.GoString(application)
	dataBytes := C.GoBytes(unsafe.Pointer(data), C.int(datalen))
	handle := C.GoBytes(unsafe.Pointer(keyHandle), C.int(keyHandleLen))

	sigR, sigS, counter, respFlags, err := backend.Sign(uint32(alg), app, handle, dataBytes, byte(flags))
	if err != nil {
		log.Printf("[SK] sk_sign: %v", err)
		return C.int(C.SSH_SK_ERR_GENERAL)
	}

	resp := (*C.struct_sk_sign_response)(C.calloc(1, C.size_t(C.sizeof_struct_sk_sign_response)))
	if resp == nil {
		return C.int(C.SSH_SK_ERR_GENERAL)
	}

	resp.flags = C.uint8_t(respFlags)
	resp.counter = C.uint32_t(counter)

	resp.sig_r = (*C.uint8_t)(C.malloc(C.size_t(len(sigR))))
	if resp.sig_r == nil {
		C.free(unsafe.Pointer(resp))
		return C.int(C.SSH_SK_ERR_GENERAL)
	}
	resp.sig_r_len = C.size_t(len(sigR))
	C.memcpy(unsafe.Pointer(resp.sig_r), unsafe.Pointer(&sigR[0]), C.size_t(len(sigR)))

	if sigS != nil { // ECDSA: return separate R and S components
		resp.sig_s = (*C.uint8_t)(C.malloc(C.size_t(len(sigS))))
		if resp.sig_s == nil {
			C.free(unsafe.Pointer(resp.sig_r))
			C.free(unsafe.Pointer(resp))
			return C.int(C.SSH_SK_ERR_GENERAL)
		}
		resp.sig_s_len = C.size_t(len(sigS))
		C.memcpy(unsafe.Pointer(resp.sig_s), unsafe.Pointer(&sigS[0]), C.size_t(len(sigS)))
	} else { // Ed25519: sig_s unused
		resp.sig_s = nil
		resp.sig_s_len = 0
	}

	*signResponse = resp
	log.Printf("[SK] sk_sign: success, counter=%d", counter)
	return C.int(0)
}

//export sk_load_resident_keys
func sk_load_resident_keys(
	pin *C.char,
	options **C.struct_sk_option,
	rks ***C.struct_sk_resident_key,
	nrks *C.size_t,
) C.int {
	_ = pin
	_ = options
	// Resident keys (keys stored on the authenticator itself) are not supported.
	*rks = nil
	*nrks = 0
	return C.int(0)
}

// optionValue searches a null-terminated sk_option array for the named key and
// returns its value, or "" if not found or options is nil.
func optionValue(options **C.struct_sk_option, name string) string {
	if options == nil {
		return ""
	}
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))

	for i := 0; ; i++ {
		opt := *(**C.struct_sk_option)(unsafe.Pointer(
			uintptr(unsafe.Pointer(options)) + uintptr(i)*unsafe.Sizeof(*options),
		))
		if opt == nil {
			break
		}
		if C.strcmp(opt.name, cName) == 0 && opt.value != nil {
			return C.GoString(opt.value)
		}
	}
	return ""
}

//export sk_free_enroll_response
func sk_free_enroll_response(r *C.struct_sk_enroll_response) {
	if r == nil {
		return
	}
	if r.public_key != nil {
		C.free(unsafe.Pointer(r.public_key))
	}
	if r.key_handle != nil {
		C.free(unsafe.Pointer(r.key_handle))
	}
	if r.signature != nil {
		C.free(unsafe.Pointer(r.signature))
	}
	if r.attestation_cert != nil {
		C.free(unsafe.Pointer(r.attestation_cert))
	}
	if r.authdata != nil {
		C.free(unsafe.Pointer(r.authdata))
	}
	C.free(unsafe.Pointer(r))
}

//export sk_free_sign_response
func sk_free_sign_response(r *C.struct_sk_sign_response) {
	if r == nil {
		return
	}
	if r.sig_r != nil {
		C.free(unsafe.Pointer(r.sig_r))
	}
	if r.sig_s != nil {
		C.free(unsafe.Pointer(r.sig_s))
	}
	C.free(unsafe.Pointer(r))
}

//export sk_free_resident_key
func sk_free_resident_key(k *C.struct_sk_resident_key) {
	_ = k
}

//export sk_free_resident_keys
func sk_free_resident_keys(rks **C.struct_sk_resident_key, nrks C.size_t) {
	_ = rks
	_ = nrks
}

func main() {}
