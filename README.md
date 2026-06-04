# PocketAgent

Use your Android phone as a hardware SSH key. Ed25519 keys are generated and stored in Android Keystore (StrongBox/TEE) and never leave the device — every SSH authentication requires a biometric tap on the phone. The desktop connects to the phone over Bluetooth Low Energy.

## How it works

```
SSH Client
  │
  ├─ SSH Agent socket (SSH_AUTH_SOCK)  ──┐
  │                                      ├─► BLE ──► Android App ──► Android Keystore
  └─ PKCS#11 provider (.so)  ────────────┘
```

The Android app runs a GATT server that speaks the SSH agent protocol. The Linux proxy connects as a GATT client and exposes the phone's keys to the desktop in two ways:

- **SSH Agent** — Unix socket; set `SSH_AUTH_SOCK` and all SSH tools work transparently.
- **PKCS#11** — a shared library any PKCS#11-capable app can load directly, no daemon needed.

## Repository layout

```
PocketAgent/
├── android/   Android app (Kotlin/Compose) — key management, BLE GATT server, biometric signing
└── proxy/     Linux desktop proxy (Go) — BLE client, SSH agent socket, PKCS#11 provider
```

## Android app

### Requirements

- Android 16+ (API 36) — required for Ed25519 Android Keystore support
- Device with StrongBox or TEE (most modern phones)

### Setup

1. Build and install the app from `android/` (Android Studio or `./gradlew installDebug`)
2. Open the app and tap **+** to generate an Ed25519 key
3. Tap **Pair device** and scan the QR code shown by `pocket-agent pair` on the desktop
4. The BLE service starts automatically and shows a persistent notification

### What the app does

- Generates Ed25519 keys inside Android Keystore — private key material is never accessible to app code
- Runs a BLE GATT server that speaks the SSH agent protocol
- Shows a biometric prompt (fingerprint/face/PIN) for every sign request
- Verifies the desktop's identity against a trust store before responding to any request

## Desktop proxy

### Requirements

- Linux with BlueZ (`bluetoothd`) and a BLE adapter
- Go 1.21+ (to build)
- GCC (for the PKCS#11 provider only)

### Building

**CLI + SSH Agent:**

```bash
cd proxy
go build ./cmd/pocket-agent/
```

**PKCS#11 shared library:**

```bash
cd proxy/pkcs11
make
# produces libpocket-pkcs11.so
```

### Pairing (one-time)

```bash
./pocket-agent pair
# Scan the QR code with the PocketAgent Android app
```

Options:

```
-label string    Device label shown on phone (default: hostname)
-config string   Config directory (default: ~/.config/pocket-agent)
-output string   Save QR code as PNG to this path
```

Keys are stored in `~/.config/pocket-agent/keys/` and reused across sessions.

### SSH Agent mode

Start the proxy:

```bash
./pocket-agent run
# prints: export SSH_AUTH_SOCK=/tmp/pocket-agent-1000.sock
```

Copy the printed line into your shell, then SSH as normal:

```bash
export SSH_AUTH_SOCK=/tmp/pocket-agent-1000.sock
ssh user@server   # biometric prompt appears on phone
```

`pocket-agent run` options:

```
-socket string   Path for the SSH agent socket (default: /tmp/pocket-agent-<uid>.sock)
-config string   Config directory (default: ~/.config/pocket-agent)
```

### PKCS#11 mode

**Option A — per-command flag:**

```bash
ssh -I /path/to/libpocket-pkcs11.so user@server
```

**Option B — load into the running ssh-agent once** (no `-I` flag needed afterwards):

```bash
ssh-add -q -s /path/to/libpocket-pkcs11.so
ssh user@server   # phone keys available automatically

# Unload when done:
ssh-add -e /path/to/libpocket-pkcs11.so
```

**Option C — `~/.ssh/config` (recommended for permanent setup):**

```
Host myserver
    HostName server.example.com
    User myuser
    PKCS11Provider /path/to/libpocket-pkcs11.so
```

**Other tools:**

```bash
# Git
export GIT_SSH_COMMAND="ssh -I /path/to/libpocket-pkcs11.so"
git clone git@github.com:user/repo.git

# SCP
scp -o PKCS11Provider=/path/to/libpocket-pkcs11.so file user@server:

# SFTP
sftp -o PKCS11Provider=/path/to/libpocket-pkcs11.so user@server
```

### Diagnostic

Verify BLE connectivity and authentication end-to-end:

```bash
./pocket-agent test
# [1/4] Device keys loaded
# [2/4] BLE connected
# [3/4] Authenticated with phone
# [4/4] Phone has 2 key(s) available
```

### Configuration

Config directory: `~/.config/pocket-agent/` (override with `-config`)

```
~/.config/pocket-agent/
└── keys/
    ├── device.key   Ed25519 private key (desktop identity for BLE auth)
    └── device.pub   Ed25519 public key
```

Generated automatically on first `pair` run.

## Troubleshooting

**BLE connection fails**

1. Check Bluetooth is enabled: `bluetoothctl show`
2. Ensure the Android app is open and the BLE service notification is visible
3. Phone must be within range (< ~10 m)
4. Verify pairing: `ls ~/.config/pocket-agent/keys/` — both files must exist

Run `./pocket-agent test` for a step-by-step diagnosis.

**SSH hangs after connecting**

The phone is waiting for biometric input. Check the Android screen for a fingerprint/face prompt. If no prompt appears, verify the app has biometric permission in Android settings.

**Empty key list / "No objects found"**

1. Open the Android app, tap **+** to create a key
2. Confirm the BLE service notification is visible
3. Retry: `pkcs11-tool --module ./libpocket-pkcs11.so --list-objects`

**"CKR_FUNCTION_FAILED" on initialize**

Device keys missing. Regenerate:

```bash
rm -rf ~/.config/pocket-agent/keys
./pocket-agent pair
```

## Security

- **Private keys never leave the phone.** Signing is performed inside Android Keystore (StrongBox/TEE); only the signature crosses BLE.
- **Per-sign biometric.** Every SSH authentication requires a fresh fingerprint/face/PIN approval — no caching, no session window.
- **QR pairing with Ed25519 verification.** The QR payload is signed by the desktop key; the app verifies it before adding the device to its trust store.
- **Session authentication.** The proxy must prove its identity with its device key before the phone responds to any agent request.
