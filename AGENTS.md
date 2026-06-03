# AGENTS

## Project Overview

PocketSSHAgent is a remote SSH agent for Android that stores Ed25519 keys in Android Keystore (StrongBox/TEE) and provides SSH agent services to Linux desktops over BLE transport. See `plan.md` for full requirements and architecture.

## Build Configuration

- Single-module Android app; only module is `:app` (see `settings.gradle.kts`)
- App entrypoint is `com.example.pocketsshagent.MainActivity`, registered in `app/src/main/AndroidManifest.xml`
- UI is Jetpack Compose; theme definitions live under `app/src/main/java/com/example/pocketsshagent/ui/theme/`
- SDK levels are unusually high (`minSdk = 36`, `targetSdk = 36`) in `app/build.gradle.kts`
- Dependency and plugin versions are managed via the version catalog at `gradle/libs.versions.toml`

## Architecture & Code Organization

### Package Structure
All code lives under `app/src/main/java/com/example/pocketsshagent/`:

- `agent/` - SSH agent protocol implementation
  - `SshAgentHandler.kt` - Handles REQUEST_IDENTITIES, SIGN_REQUEST, custom auth messages
  - `AgentMessage.kt` - Message type definitions and serialization
  - `SshWireFormat.kt` - SSH wire format encoding/decoding (uint32, strings, keys, signatures)
  
- `ble/` - Bluetooth Low Energy transport
  - `BleAgentService.kt` - Foreground service with GATT server, MTU negotiation, frame chunking/reassembly
  - `BleUuids.kt` - Service and characteristic UUIDs
  - `BleFraming.kt` - Length-prefixed framing for agent messages over BLE
  
- `crypto/` - Key management and signing
  - `KeyManager.kt` - Android Keystore wrapper for Ed25519 key generation, signing, deletion
  - `BiometricAgentCallback.kt` - BiometricPrompt integration with strict per-request authentication
  
- `data/` - Data persistence
  - `KeyMetadataStore.kt` - SharedPreferences-backed metadata store (label, creation time, hardware-backed flag, last used)
  
- `model/` - Data models
  - `KeyMetadata.kt` - Key metadata data class
  
- `pairing/` - Device pairing and trust
  - `PairingProtocol.kt` - QR payload parsing and cryptographic verification
  - `TrustStore.kt` - SharedPreferences-backed device trust store
  - `QrScannerView.kt` - CameraX + ML Kit barcode scanning
  - `PairingScreen.kt` - Compose UI for device management
  
- `ui/theme/` - Compose theme (Color.kt, Theme.kt, Type.kt)
- `MainActivity.kt` - Main UI with key list, create key dialog, pairing navigation

### Key Implementation Details

**Cryptography:**
- Ed25519 keys only, generated in Android Keystore with `setUserAuthenticationRequired(true)` and `setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG | DEVICE_CREDENTIAL)`
- StrongBox/TEE detection via `isInsideSecureHardware` property
- Private keys never leave Keystore; signing requires biometric approval every time
- Public keys exported in SSH authorized_keys format and as SHA256 fingerprints

**BLE Protocol:**
- Custom GATT service with RX (write) and TX (notify) characteristics
- 4-byte length prefix framing; chunks split across BLE MTU boundaries
- Per-device MTU tracking and reassembly buffers
- Session authentication using trust store before serving agent requests

**SSH Agent Protocol:**
- Implements OpenSSH agent protocol subset: REQUEST_IDENTITIES (11), SIGN_REQUEST (13)
- Custom POCKET_AUTH_REQUEST (100) for session authentication
- Wire format follows OpenSSH spec (uint32 length prefix, SSH string encoding)
- Ed25519 public keys encoded as SSH format with "ssh-ed25519" type string
- Signatures wrapped in SSH signature format

**Security Model:**
- Strict biometric per signing request (zero timeout, no session caching)
- QR-based pairing with Ed25519 signature verification over nonce
- Trust store gates access to agent operations
- Foreground service ensures BLE remains active

### Current Architecture Patterns

**Data Flow:**
- UI → KeyManager/TrustStore → Keystore/SharedPreferences (no ViewModels or Repositories)
- BLE service → SshAgentHandler → KeyManager → BiometricPrompt → Keystore signing
- Direct state management with `remember { mutableStateOf() }` in Composables

**State Management:**
- No ViewModel architecture; state held directly in Composables
- Service state managed internally with mutable properties
- No central state store or reactive streams

## Implementation Status

### Completed (Milestones 1-4, ~95% core functionality)
- Ed25519 key generation, listing, deletion with StrongBox/TEE support
- Biometric-gated signing with strict per-request authentication
- BLE GATT service with MTU negotiation, chunking, reassembly
- QR pairing with cryptographic verification
- Trust store for paired devices
- SSH agent protocol (REQUEST_IDENTITIES, SIGN_REQUEST, wire format)
- Basic Compose UI (key list, pairing screen)
- Unit tests for agent messages, wire format, BLE framing

### Missing / Not Implemented
- **Architecture:** No ViewModels, Repositories, or Navigation Component
- **UI:** No dedicated signing prompt screen, key detail screen, or service status indicator
- **Features:** No key renaming, per-device access control, audit logging, encrypted metadata storage
- **Testing:** No integration tests with actual SSH client, no UI tests
- **Polish:** No README, user documentation, settings screen, or localization
- **Desktop:** Go proxy exists in `proxy/` but integration untested

## Companion Desktop Proxy

A Linux Go proxy exists in the `proxy/` directory that:
- Connects to phone over BLE
- Exposes local SSH agent socket (`SSH_AUTH_SOCK`)
- Translates OpenSSH agent protocol to BLE transport
- Generates QR codes for pairing

(See `proxy/` for Go codebase)

## Testing

Unit tests in `app/src/test/java/com/example/pocketsshagent/`:
- `AgentMessageTest.kt` - Protocol message parsing
- `SshWireFormatTest.kt` - Encoding/decoding correctness
- `BleFramingTest.kt` - Chunking and reassembly logic

Run with: `./gradlew test`

No integration or end-to-end tests currently exist.

## Permissions & Manifest

Required permissions (see `AndroidManifest.xml`):
- `BLUETOOTH_ADVERTISE`, `BLUETOOTH_CONNECT` - BLE GATT server
- `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_CONNECTED_DEVICE` - Persistent BLE service
- `POST_NOTIFICATIONS` - Foreground service notification
- `CAMERA` - QR code scanning for pairing

BleAgentService registered as `connectedDevice` foreground service type.

## Known Constraints

- Only Ed25519 keys supported (no RSA or ECDSA)
- BLE transport only (no Wi-Fi or USB)
- Requires `minSdk = 36` (Android 16+) due to Ed25519 Keystore API
- No key import or backup functionality
- Metadata stored in plain SharedPreferences (not encrypted)
- No session timeouts or rate limiting
