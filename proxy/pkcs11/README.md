# PocketSSHAgent PKCS#11 Provider

PKCS#11 cryptographic token provider that exposes Android Keystore keys over BLE for SSH authentication.

## Overview

This provider implements the PKCS#11 v2.40 standard, allowing OpenSSH and other applications to use Ed25519 keys stored in Android Keystore (StrongBox/TEE) as if they were in a hardware security token.

**Architecture:**
```
SSH Client → libpocket-pkcs11.so → BLE → Android App → Android Keystore
```

## Prerequisites

- **Go 1.21+** (for building)
- **GCC** (C compiler)
- **Android App** - PocketSSHAgent must be installed, paired, and running
- **BLE Adapter** - Bluetooth Low Energy support on Linux desktop

## Building

```bash
cd proxy/pkcs11
make
```

This produces `libpocket-pkcs11.so` in the current directory.

**Build output:**
- `libpocket-pkcs11.so` - PKCS#11 provider (load this in SSH)
- `libbridge.a` - Go static library (linked into .so)
- `libbridge.h` - CGO header (generated automatically)

## Testing

### 1. Test with pkcs11-tool

List available slots:
```bash
pkcs11-tool --module ./libpocket-pkcs11.so --list-slots
```

**Expected output:**
```
Available slots:
Slot 0 (0x0): PocketSSHAgent Slot
  token label        : PocketSSHAgent Token
  token manufacturer : PocketSSHAgent
  token model        : v1.0
  token flags        : login required, token initialized, user pin initialized
```

List objects (keys):
```bash
pkcs11-tool --module ./libpocket-pkcs11.so --list-objects
```

**Expected output:**
```
Public Key Object; EC_EDWARDS EC_POINT 256 bits
  EC_POINT:   ...
  EC_PARAMS:  ...
  label:      my-phone-key
  ID:         key-0
Private Key Object; EC_EDWARDS
  label:      my-phone-key
  ID:         key-0
  Usage:      sign
```

### 2. Test with SSH

**One-time SSH connection:**
```bash
ssh -I ./libpocket-pkcs11.so user@hostname
```

**SSH config (recommended):**

Add to `~/.ssh/config`:
```
Host myserver
    HostName server.example.com
    User myuser
    PKCS11Provider /path/to/libpocket-pkcs11.so
```

Then simply:
```bash
ssh myserver
```

**What happens:**
1. SSH loads the PKCS#11 provider
2. Provider connects to Android via BLE
3. SSH requests signature from provider
4. Provider sends sign request to Android
5. **Android shows biometric prompt** 👆
6. User authenticates with fingerprint/face
7. Android Keystore signs the challenge
8. Signature returned to SSH
9. SSH completes authentication

## Configuration

The provider uses the same configuration as the SSH agent:

**Config location:** `~/.config/pocket-agent/keys`

This directory contains:
- `device.key` - Ed25519 private key for BLE authentication
- `device.pub` - Ed25519 public key

**Pairing:**

If not already paired, run:
```bash
cd ../
./pocket-agent pair
# Scan QR code with Android app
```

## Usage with Different Applications

### OpenSSH Client
```bash
ssh -I /path/to/libpocket-pkcs11.so user@server
```

### Git over SSH
```bash
export GIT_SSH_COMMAND="ssh -I /path/to/libpocket-pkcs11.so"
git clone git@github.com:user/repo.git
```

### SCP
```bash
scp -o PKCS11Provider=/path/to/libpocket-pkcs11.so file user@server:
```

### SFTP
```bash
sftp -o PKCS11Provider=/path/to/libpocket-pkcs11.so user@server
```

## Logging

The provider includes verbose logging to help with debugging.

**Enable Go logs:**
```bash
export GODEBUG=cgocheck=0
ssh -I ./libpocket-pkcs11.so user@server 2>&1 | grep -E '\[PKCS11\]|\[CGO\]'
```

**Log messages:**
- `[PKCS11]` - Backend operations (Go layer)
- `[CGO]` - Bridge layer (C ↔ Go)

## Troubleshooting

### "Connection refused" or BLE errors

**Check:**
1. Android app is running and BLE service started
2. Bluetooth is enabled on desktop
3. Phone is in range (< 10 meters)
4. Paired successfully (QR code scanned)

**Fix:**
```bash
# Ensure pairing exists
ls ~/.config/pocket-agent/keys/
# Should show: device.key  device.pub

# Test BLE connection with SSH agent
cd ../
./pocket-agent test
```

### "CKR_FUNCTION_FAILED" during C_Initialize

**Cause:** Cannot load device keys or connect to BLE

**Fix:**
```bash
# Check device keys exist
cat ~/.config/pocket-agent/keys/device.pub

# Regenerate if needed
rm ~/.config/pocket-agent/keys/*
./pocket-agent pair
```

### "No objects found" or empty key list

**Cause:** Android app has no keys or not connected

**Fix:**
1. Open Android app
2. Create an Ed25519 key (tap "+" button)
3. Ensure BLE service is running (notification visible)
4. Retry: `pkcs11-tool --module ./libpocket-pkcs11.so --list-objects`

### SSH hangs during connection

**Cause:** Waiting for biometric authentication on Android

**Fix:**
- Check Android screen for biometric prompt
- Authenticate with fingerprint/face/PIN
- If no prompt appears, check Android app permissions

### "CKR_OPERATION_NOT_INITIALIZED" during signing

**Cause:** C_SignInit not called before C_Sign

**Fix:** This is usually an SSH client issue. Try:
```bash
ssh -vvv -I ./libpocket-pkcs11.so user@server
# Look for PKCS#11 debug messages
```

## Implementation Details

### Supported PKCS#11 Functions

**Core:**
- `C_Initialize` / `C_Finalize` - Module lifecycle
- `C_GetInfo` / `C_GetSlotList` / `C_GetTokenInfo` - Discovery
- `C_OpenSession` / `C_CloseSession` - Session management
- `C_Login` / `C_Logout` - Authentication (triggers Android biometric)

**Object Management:**
- `C_FindObjectsInit` / `C_FindObjects` / `C_FindObjectsFinal` - Key enumeration
- `C_GetAttributeValue` - Read key attributes (label, ID, public key)

**Signing:**
- `C_SignInit` - Initialize signing with CKM_EDDSA mechanism
- `C_Sign` - Perform Ed25519 signature (triggers Android biometric)

**Unsupported (returns CKR_FUNCTION_NOT_SUPPORTED):**
- Encryption/decryption (C_Encrypt, C_Decrypt)
- Key generation via PKCS#11 (use Android app)
- Verification (C_Verify)
- All other cryptographic operations

### Key Attributes

**Public Key Object:**
- `CKA_CLASS` = CKO_PUBLIC_KEY
- `CKA_KEY_TYPE` = CKK_EC_EDWARDS (Ed25519)
- `CKA_LABEL` = Key label from Android
- `CKA_ID` = Unique identifier
- `CKA_EC_POINT` = 32-byte Ed25519 public key
- `CKA_SIGN` = FALSE
- `CKA_TOKEN` = TRUE

**Private Key Object:**
- `CKA_CLASS` = CKO_PRIVATE_KEY
- `CKA_KEY_TYPE` = CKK_EC_EDWARDS
- `CKA_LABEL` = Key label from Android
- `CKA_ID` = Unique identifier (matches public key)
- `CKA_SIGN` = TRUE
- `CKA_PRIVATE` = TRUE
- `CKA_SENSITIVE` = TRUE
- `CKA_EXTRACTABLE` = FALSE
- `CKA_TOKEN` = TRUE

### Protocol Flow

**Initialization:**
```
C_Initialize
  └─> GoInitialize
      └─> LoadPrivateKey (from ~/.config/pocket-agent/keys)
      └─> pkcs11.Initialize
          └─> Start BLE ConnectionManager
```

**Key Discovery:**
```
C_FindObjectsInit
  └─> GoFindObjectsInit
      └─> backend.FindObjectsInit
          └─> backend.LoadKeys
              └─> BLE: REQUEST_IDENTITIES (type 11)
              └─> Parse SSH key blobs
              └─> Create CKO_PUBLIC_KEY and CKO_PRIVATE_KEY objects
```

**Signing:**
```
C_SignInit(mechanism=CKM_EDDSA, hKey=privkey_handle)
  └─> GoSignInit
      └─> backend.SignInit (store key handle)

C_Sign(data, signature)
  └─> GoSign
      └─> backend.Sign
          └─> Build SSH SIGN_REQUEST (type 13)
          └─> BLE: Send to Android
          └─> Android: Show biometric prompt 👆
          └─> User authenticates
          └─> Android Keystore: Sign with hardware key
          └─> BLE: Receive SIGN_RESPONSE (type 14)
          └─> Parse SSH signature format
          └─> Return raw 64-byte Ed25519 signature
```

## Performance

**Latency:**
- Key discovery: ~200-500ms (BLE scan + load keys)
- Signing: ~1-3s (BLE roundtrip + biometric prompt + Keystore signing)

**Comparison:**
- SSH agent (same BLE transport): ~1-3s per signature
- PKCS#11 provider: ~1-3s per signature (identical backend)

No significant performance difference between SSH agent and PKCS#11 interfaces.

## Security Considerations

**Private keys never leave Android Keystore:**
- Keys stored in hardware security module (StrongBox/TEE)
- Signing operations performed in secure environment
- Private key material never transmitted over BLE

**Biometric authentication:**
- Every signature requires Android biometric approval
- No PIN caching or session persistence
- User presence verified for each operation

**BLE transport security:**
- QR-based pairing with Ed25519 signature verification
- Session authentication before accepting requests
- Trust store gates access to signing operations

## Comparison: PKCS#11 vs SSH Agent

| Feature | SSH Agent | PKCS#11 Provider |
|---------|-----------|------------------|
| **SSH Support** | ✅ Native | ✅ Via PKCS#11 |
| **Setup** | `export SSH_AUTH_SOCK` | `ssh -I provider.so` or config |
| **Other Apps** | SSH only | Potentially any PKCS#11 app |
| **Implementation** | ~1,500 LOC (done) | ~4,000 LOC (new) |
| **Performance** | ~1-3s per sign | ~1-3s per sign |
| **Protocol** | SSH agent protocol | PKCS#11 standard |

**Recommendation:** Use SSH agent for simplicity. Use PKCS#11 if you need compatibility with other applications that support PKCS#11 but not SSH agent protocol.

## License

Same as PocketSSHAgent project.

## Support

For issues or questions, see main project documentation.
