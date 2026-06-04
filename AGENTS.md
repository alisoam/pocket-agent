# AGENTS

## Project Overview

PocketSSHAgent is a remote SSH agent for Android that stores Ed25519 keys in Android Keystore (StrongBox/TEE) and provides SSH agent services to Linux desktops over BLE transport.

## Repository Layout

```
PocketSSHAgent/
├── android/   ← Android app (Kotlin/Compose)
└── proxy/     ← Linux desktop proxy (Go)
```

## Android App

### Build Configuration

- Single-module Android app; only module is `:app` (see `android/settings.gradle.kts`)
- App entrypoint is `com.example.pocketsshagent.MainActivity`, registered in `android/app/src/main/AndroidManifest.xml`
- UI is Jetpack Compose; theme definitions live under `android/app/src/main/java/com/example/pocketsshagent/ui/theme/`
- SDK levels are unusually high (`minSdk = 36`, `targetSdk = 36`) in `android/app/build.gradle.kts`
- Dependency and plugin versions are managed via the version catalog at `android/gradle/libs.versions.toml`

### Package Structure
All code lives under `android/app/src/main/java/com/example/pocketsshagent/`:

- `agent/` - SSH agent protocol implementation
  - `SshAgentHandler.kt` - Handles REQUEST_IDENTITIES, SIGN_REQUEST, custom auth messages
  - `AgentMessage.kt` - Message type definitions and serialization
  - `SshWireFormat.kt` - SSH wire format encoding/decoding (uint32, strings, keys, signatures)
  - `SshPublicKeyUtils.kt` - Public key formatting utilities (authorized_keys format, fingerprints)
  
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
- Frame layout: `[4B ble_len][4B corr_id][4B ssh_len][ssh_payload]` — correlation ID matches responses to senders when multiple processes share the same BLE connection

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

## Android Implementation Status

### Completed
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

## Android Testing

Unit tests in `android/app/src/test/java/com/example/pocketsshagent/`:
- `AgentMessageTest.kt` - Protocol message parsing
- `SshWireFormatTest.kt` - Encoding/decoding correctness
- `BleFramingTest.kt` - Chunking and reassembly logic

Run with: `cd android && ./gradlew test`

No integration or end-to-end tests currently exist.

## Android Permissions & Manifest

Required permissions (see `android/app/src/main/AndroidManifest.xml`):
- `BLUETOOTH_ADVERTISE`, `BLUETOOTH_CONNECT` - BLE GATT server
- `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_CONNECTED_DEVICE` - Persistent BLE service
- `POST_NOTIFICATIONS` - Foreground service notification
- `CAMERA` - QR code scanning for pairing

BleAgentService registered as `connectedDevice` foreground service type.

## Desktop Proxy (`proxy/`)

A Linux Go proxy that connects to the phone over BLE and makes the phone's SSH keys available to the desktop. Two integration modes are supported:

### SSH Agent mode (primary)
Exposes a Unix domain socket as `SSH_AUTH_SOCK`. SSH clients talk to the socket; the proxy forwards requests over BLE to the phone.

### PKCS#11 mode
A shared library (`libpocket-pkcs11.so`) that any PKCS#11-capable application (OpenSSH, git) can load directly without a background daemon.

### Proxy Architecture

```
proxy/
├── cmd/pocket-agent/main.go   ← CLI: pair / run / test subcommands
├── internal/
│   ├── agent/server.go        ← Unix socket server (SSH agent protocol)
│   ├── ble/
│   │   ├── client.go          ← BLE GATT client (scan, connect, notify)
│   │   └── manager.go         ← Auto-reconnect with exponential backoff + keepalive
│   └── pairing/pairing.go     ← Key gen/load, QR code generation
└── pkcs11/
    ├── provider.c             ← C PKCS#11 API implementation (70+ functions)
    ├── bridge.go              ← CGO bridge: C ↔ Go
    ├── internal/pkcs11/       ← Go backend: sessions, object model, BLE signing
    └── libpocket-pkcs11.so    ← Built shared library
```

### Proxy Key Components

**`internal/ble/client.go` — BLE Client**
- Scans for the phone's custom GATT service UUID
- Handles MTU-chunked writes and notification-based reads
- 4-byte correlation IDs allow multiple processes to share one BLE connection
- 60-second timeout for sign requests (biometric required), 10s for others
- `Ping()` sends REQUEST_IDENTITIES as a lightweight keepalive

**`internal/ble/manager.go` — ConnectionManager**
- Wraps `Client` with automatic reconnection
- States: Disconnected → Connecting → Authenticating → Connected
- Exponential backoff (1s → 2s → 4s → ... → 30s cap) with ±10% jitter
- Keepalive ping every 30 seconds of idle time
- Implements `agent.Transport` interface

**`internal/agent/server.go` — SSH Agent Server**
- Unix socket server accepting OpenSSH agent protocol connections
- Pre-hashes ECDSA P-256 sign data to SHA-256 before forwarding (Android signs with `NONEwithECDSA`)
- Sends `SSH_AGENT_FAILURE` (type 5) on transport errors so SSH clients retry gracefully

**`internal/pairing/pairing.go` — Pairing**
- Generates or loads an Ed25519 keypair from `~/.config/pocket-agent/keys/`
- Produces QR code (terminal + optional PNG) containing: version, public key (X.509/PKIX), nonce, label, signature
- Android app scans QR, verifies signature, adds device to trust store

**`pkcs11/` — PKCS#11 Provider**
- C layer (`provider.c`) implements the PKCS#11 API; routes calls to Go via CGO bridge
- Each Android key becomes two objects: `CKO_PUBLIC_KEY` and `CKO_PRIVATE_KEY`
- Reuses the same BLE + SSH agent backend as the socket mode
- Build: `cd proxy/pkcs11 && make` → produces `libpocket-pkcs11.so`
- Usage: `ssh -I /path/to/libpocket-pkcs11.so user@host`

### Proxy CLI

```
pocket-agent pair   # Generate QR code for phone pairing
pocket-agent run    # Start SSH agent socket (prints export SSH_AUTH_SOCK=...)
pocket-agent test   # Diagnostic: BLE connect + auth + list keys
```

Config dir: `~/.config/pocket-agent/` (keys stored here)

### Proxy Dependencies

- `tinygo.org/x/bluetooth` — BLE GATT client (Linux/BlueZ via D-Bus)
- `github.com/skip2/go-qrcode` — QR code generation

Build: `cd proxy && go build ./cmd/pocket-agent/`

## Known Constraints

- Only Ed25519 keys supported on Android (no RSA or ECDSA)
- BLE transport only (no Wi-Fi or USB)
- Requires `minSdk = 36` (Android 16+) due to Ed25519 Keystore API
- No key import or backup functionality
- Android metadata stored in plain SharedPreferences (not encrypted)
- No session timeouts or rate limiting on Android
- PKCS#11 provider: Linux x86-64 only (CGO, links against BlueZ)
