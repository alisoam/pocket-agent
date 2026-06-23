package main

/*
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

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
	struct sk_enroll_response key;
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
	"encoding/binary"
	"log"
	"unsafe"
)

//export sk_api_version
func sk_api_version() C.uint32_t {
	return C.uint32_t(0x000a0000)
}

// cBytes copies b into a freshly C.malloc'd buffer, returning the pointer, its
// length, and whether allocation succeeded. An empty slice yields (nil, 0, true)
// so callers never take &b[0] on a zero-length slice (which panics across the
// cgo boundary into OpenSSH).
func cBytes(b []byte) (*C.uint8_t, C.size_t, bool) {
	if len(b) == 0 {
		return nil, 0, true
	}
	p := C.malloc(C.size_t(len(b)))
	if p == nil {
		return nil, 0, false
	}
	C.memcpy(p, unsafe.Pointer(&b[0]), C.size_t(len(b)))
	return (*C.uint8_t)(p), C.size_t(len(b)), true
}

// freeResidentArray unwinds a partially built resident-key array: it frees the
// first count populated entries and the array itself.
func freeResidentArray(arr **C.struct_sk_resident_key, count int, ptrSize uintptr) {
	for j := 0; j < count; j++ {
		elemPtr := *(**C.struct_sk_resident_key)(unsafe.Pointer(
			uintptr(unsafe.Pointer(arr)) + uintptr(j)*ptrSize,
		))
		sk_free_resident_key(elemPtr)
	}
	C.free(unsafe.Pointer(arr))
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
	_ = pin
	_ = options

	log.Printf("[SK-TERMUX] sk_enroll: alg=%d flags=0x%02x", alg, flags)

	if uint32(alg) != 0 && uint32(alg) != 1 {
		return C.int(C.SSH_SK_ERR_UNSUPPORTED)
	}

	backend := getBackend()
	if backend == nil {
		return C.int(C.SSH_SK_ERR_DEVICE_NOT_FOUND)
	}

	app := C.GoString(application)
	label := optionValue(options, "label")
	var challengeBytes []byte
	if challenge != nil && challengeLen > 0 {
		challengeBytes = C.GoBytes(unsafe.Pointer(challenge), C.int(challengeLen))
	}

	pubkey, keyHandle, actualAlg, attestationChain, err := backend.Enroll(app, uint32(alg), byte(flags), label, challengeBytes)
	if err != nil {
		log.Printf("[SK-TERMUX] sk_enroll: %v", err)
		return C.int(C.SSH_SK_ERR_GENERAL)
	}
	if actualAlg != uint32(alg) {
		log.Printf("[SK-TERMUX] sk_enroll: alg mismatch (requested %d, got %d)", alg, actualAlg)
		return C.int(C.SSH_SK_ERR_UNSUPPORTED)
	}

	resp := (*C.struct_sk_enroll_response)(C.calloc(1, C.size_t(C.sizeof_struct_sk_enroll_response)))
	if resp == nil {
		return C.int(C.SSH_SK_ERR_GENERAL)
	}

	resp.flags = flags

	pub, pubLen, ok := cBytes(pubkey)
	if !ok {
		C.free(unsafe.Pointer(resp))
		return C.int(C.SSH_SK_ERR_GENERAL)
	}
	resp.public_key = pub
	resp.public_key_len = pubLen

	handle, handleLen, ok := cBytes(keyHandle)
	if !ok {
		C.free(unsafe.Pointer(resp.public_key))
		C.free(unsafe.Pointer(resp))
		return C.int(C.SSH_SK_ERR_GENERAL)
	}
	resp.key_handle = handle
	resp.key_handle_len = handleLen

	resp.signature = nil
	resp.signature_len = 0
	resp.attestation_cert = nil
	resp.attestation_cert_len = 0
	resp.authdata = nil
	resp.authdata_len = 0

	if len(attestationChain) > 0 {
		cert, certLen, ok := cBytes(attestationChain[0])
		if !ok {
			C.free(unsafe.Pointer(resp.key_handle))
			C.free(unsafe.Pointer(resp.public_key))
			C.free(unsafe.Pointer(resp))
			return C.int(C.SSH_SK_ERR_GENERAL)
		}
		resp.attestation_cert = cert
		resp.attestation_cert_len = certLen

		if len(attestationChain) > 1 {
			intermediates := attestationChain[1:]
			authSize := 1
			for _, c := range intermediates {
				authSize += 2 + len(c)
			}
			authBuf := make([]byte, authSize)
			authBuf[0] = byte(len(intermediates))
			aOff := 1
			for _, c := range intermediates {
				binary.BigEndian.PutUint16(authBuf[aOff:], uint16(len(c)))
				aOff += 2
				copy(authBuf[aOff:], c)
				aOff += len(c)
			}
			authData, authLen, ok := cBytes(authBuf)
			if !ok {
				C.free(unsafe.Pointer(resp.attestation_cert))
				C.free(unsafe.Pointer(resp.key_handle))
				C.free(unsafe.Pointer(resp.public_key))
				C.free(unsafe.Pointer(resp))
				return C.int(C.SSH_SK_ERR_GENERAL)
			}
			resp.authdata = authData
			resp.authdata_len = authLen
		}
	}

	*enrollResponse = resp
	log.Printf("[SK-TERMUX] sk_enroll: success, handle=%q", string(keyHandle))
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

	log.Printf("[SK-TERMUX] sk_sign: alg=%d datalen=%d flags=0x%02x", alg, datalen, flags)

	if uint32(alg) != 0 && uint32(alg) != 1 {
		return C.int(C.SSH_SK_ERR_UNSUPPORTED)
	}

	backend := getBackend()
	if backend == nil {
		return C.int(C.SSH_SK_ERR_DEVICE_NOT_FOUND)
	}

	app := C.GoString(application)
	dataBytes := C.GoBytes(unsafe.Pointer(data), C.int(datalen))
	handle := C.GoBytes(unsafe.Pointer(keyHandle), C.int(keyHandleLen))

	sigR, sigS, counter, respFlags, err := backend.Sign(uint32(alg), app, handle, dataBytes, byte(flags))
	if err != nil {
		log.Printf("[SK-TERMUX] sk_sign: %v", err)
		return C.int(C.SSH_SK_ERR_GENERAL)
	}

	resp := (*C.struct_sk_sign_response)(C.calloc(1, C.size_t(C.sizeof_struct_sk_sign_response)))
	if resp == nil {
		return C.int(C.SSH_SK_ERR_GENERAL)
	}

	resp.flags = C.uint8_t(respFlags)
	resp.counter = C.uint32_t(counter)

	sr, srLen, ok := cBytes(sigR)
	if !ok {
		C.free(unsafe.Pointer(resp))
		return C.int(C.SSH_SK_ERR_GENERAL)
	}
	resp.sig_r = sr
	resp.sig_r_len = srLen

	if sigS != nil {
		ss, ssLen, ok := cBytes(sigS)
		if !ok {
			C.free(unsafe.Pointer(resp.sig_r))
			C.free(unsafe.Pointer(resp))
			return C.int(C.SSH_SK_ERR_GENERAL)
		}
		resp.sig_s = ss
		resp.sig_s_len = ssLen
	} else {
		resp.sig_s = nil
		resp.sig_s_len = 0
	}

	*signResponse = resp
	log.Printf("[SK-TERMUX] sk_sign: success, counter=%d", counter)
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

	log.Println("[SK-TERMUX] sk_load_resident_keys")

	backend := getBackend()
	if backend == nil {
		*rks = nil
		*nrks = 0
		return C.int(C.SSH_SK_ERR_DEVICE_NOT_FOUND)
	}

	keys, err := backend.LoadResidentKeys()
	if err != nil {
		log.Printf("[SK-TERMUX] sk_load_resident_keys: %v", err)
		*rks = nil
		*nrks = 0
		return C.int(C.SSH_SK_ERR_GENERAL)
	}

	if len(keys) == 0 {
		*rks = nil
		*nrks = 0
		return C.int(0)
	}

	n := len(keys)
	ptrSize := unsafe.Sizeof((*C.struct_sk_resident_key)(nil))
	arr := (**C.struct_sk_resident_key)(C.calloc(C.size_t(n), C.size_t(ptrSize)))
	if arr == nil {
		return C.int(C.SSH_SK_ERR_GENERAL)
	}

	for i, k := range keys {
		rk := (*C.struct_sk_resident_key)(C.calloc(1, C.size_t(C.sizeof_struct_sk_resident_key)))
		if rk == nil {
			freeResidentArray(arr, i, ptrSize)
			return C.int(C.SSH_SK_ERR_GENERAL)
		}

		rk.alg = C.uint32_t(k.Alg)
		rk.slot = 0
		rk.application = C.CString(k.App)
		rk.flags = C.uint8_t(k.Flags)
		rk.user_id = nil
		rk.user_id_len = 0
		rk.key.flags = C.uint8_t(k.Flags)

		pub, pubLen, ok := cBytes(k.PubKey)
		if !ok {
			C.free(unsafe.Pointer(rk.application))
			C.free(unsafe.Pointer(rk))
			freeResidentArray(arr, i, ptrSize)
			return C.int(C.SSH_SK_ERR_GENERAL)
		}
		rk.key.public_key = pub
		rk.key.public_key_len = pubLen

		handle, handleLen, ok := cBytes(k.Handle)
		if !ok {
			C.free(unsafe.Pointer(rk.key.public_key))
			C.free(unsafe.Pointer(rk.application))
			C.free(unsafe.Pointer(rk))
			freeResidentArray(arr, i, ptrSize)
			return C.int(C.SSH_SK_ERR_GENERAL)
		}
		rk.key.key_handle = handle
		rk.key.key_handle_len = handleLen

		rk.key.signature = nil
		rk.key.signature_len = 0
		rk.key.attestation_cert = nil
		rk.key.attestation_cert_len = 0
		rk.key.authdata = nil
		rk.key.authdata_len = 0

		elemPtr := (**C.struct_sk_resident_key)(unsafe.Pointer(
			uintptr(unsafe.Pointer(arr)) + uintptr(i)*ptrSize,
		))
		*elemPtr = rk
	}

	*rks = arr
	*nrks = C.size_t(n)
	log.Printf("[SK-TERMUX] sk_load_resident_keys: returning %d keys", n)
	return C.int(0)
}

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
	if k == nil {
		return
	}
	if k.application != nil {
		C.free(unsafe.Pointer(k.application))
	}
	if k.key.public_key != nil {
		C.free(unsafe.Pointer(k.key.public_key))
	}
	if k.key.key_handle != nil {
		C.free(unsafe.Pointer(k.key.key_handle))
	}
	if k.user_id != nil {
		C.free(unsafe.Pointer(k.user_id))
	}
	C.free(unsafe.Pointer(k))
}

//export sk_free_resident_keys
func sk_free_resident_keys(rks **C.struct_sk_resident_key, nrks C.size_t) {
	if rks == nil {
		return
	}
	ptrSize := unsafe.Sizeof((*C.struct_sk_resident_key)(nil))
	for i := 0; i < int(nrks); i++ {
		elemPtr := *(**C.struct_sk_resident_key)(unsafe.Pointer(
			uintptr(unsafe.Pointer(rks)) + uintptr(i)*ptrSize,
		))
		sk_free_resident_key(elemPtr)
	}
	C.free(unsafe.Pointer(rks))
}

func main() {}
