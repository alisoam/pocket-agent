# PocketKey

> **Note:** This is a hobby project — not audited, not production-ready. Use at your own risk.

Use your Android phone as a hardware SSH security key — the same role a YubiKey plays, but over Bluetooth. Ed25519 and ECDSA keys are generated inside Android Keystore (StrongBox/TEE) and never leave the device. Every SSH authentication requires a biometric tap on the phone.

The phone implements the OpenSSH SecurityKey (FIDO2-over-BLE) protocol, so `ssh-keygen`, `ssh`, and any OpenSSH tool treat it exactly like a hardware token.

## How it works

```
ssh-keygen / ssh
      │
      └─ SecurityKeyProvider (libpocket-sk.so)
              │
              └─ BLE ──► Android App ──► Android Keystore (TEE / StrongBox)
```

When `ssh-keygen -t ed25519-sk` runs, it contacts the SK provider, which relays the request to the phone over BLE. The phone prompts for biometric confirmation, generates the key in Keystore, and returns only the public key and a key handle. The private key never crosses BLE.

Authentication works the same way: the provider sends the signing input to the phone, the phone shows a biometric prompt, signs inside Keystore, and returns only the signature.

## Repository layout

```
PocketKey/
├── android/   Android app (Kotlin/Compose) — key management, BLE GATT server, biometric signing
├── proxy/     Linux desktop proxy (Go + C) — BLE client, OpenSSH SK provider
│   ├── cmd/pocket-agent/   CLI for pairing, diagnostics, and attestation verification
│   ├── internal/
│   │   ├── ble/            BLE GATT client with auto-reconnect and encrypted transport
│   │   └── pairing/        Ed25519 device key management and QR code generation
│   └── sk/                 libpocket-sk.so — OpenSSH SecurityKeyProvider shared library
└── termux/    On-device Termux proxy (Go) — SK provider via Android broadcast IPC
    └── sk/                 libpocket-sk.so — SecurityKeyProvider for Termux (no BLE needed)
```

## Android app

### Requirements

- Android 16+ (API 36) — required for Ed25519 Android Keystore support
- Device with StrongBox or TEE (most modern phones qualify)

### Setup

1. Build and install from `android/` with Android Studio or `./gradlew installDebug`
2. Open the app and pair your desktop: tap **Devices → +** and scan the QR code from `pocket-agent pair`
3. The BLE service starts automatically and shows a persistent notification

### Key management

Keys can be created in two ways:

- **From the phone** — tap **+** in the key list, choose a label, algorithm (Ed25519 or ECDSA), and whether the key is **resident** or **non-resident**.
- **From the desktop** — run `ssh-keygen -t ed25519-sk -w ./libpocket-sk.so`. Add `-O resident` for a resident key. The phone shows an **Allow / Deny** dialog before generating the key.

**Resident vs non-resident:**
- **Resident** keys are discoverable — download them to any machine with `ssh-keygen -K -w ./libpocket-sk.so`.
- **Non-resident** keys require the handle file (`~/.ssh/id_ed25519_sk`) to be present on each machine.

Tap a key row to access:
- **Public Key** — fingerprint and `authorized_keys` line, ready to copy
- **Handle** — the OpenSSH private key file (`-----BEGIN OPENSSH PRIVATE KEY-----`) to place in `~/.ssh/id_ed25519_sk`
- **Rename** — change the display label
- **Delete** — remove the key from Keystore

## Desktop proxy

### Requirements

- Linux with BlueZ (`bluetoothd`) and a BLE adapter
- Go 1.21+
- GCC (for the SK provider)

### Build

```bash
cd proxy

# CLI (pair, test)
go build ./cmd/pocket-agent/

# SK provider shared library
cd sk && make
# produces libpocket-sk.so
```

### Pairing (one-time)

```bash
./pocket-agent pair
# Displays a QR code — scan it with the PocketKey app
```

Options:

```
-label string    Device label shown on phone (default: hostname)
-config string   Config directory (default: ~/.config/pocket-agent)
-output string   Save QR code as PNG to this path
```

Keys are stored in `~/.config/pocket-agent/keys/` and reused across sessions.

### Creating an SSH key

```bash
# Ed25519 (recommended)
ssh-keygen -t ed25519-sk -w ./sk/libpocket-sk.so

# ECDSA P-256
ssh-keygen -t ecdsa-sk -w ./sk/libpocket-sk.so

# Resident key (downloadable to any machine later)
ssh-keygen -t ed25519-sk -O resident -w ./sk/libpocket-sk.so
```

The phone will show an **Allow / Deny** dialog. On approval it generates the key, and `ssh-keygen` writes the standard key files (`~/.ssh/id_ed25519_sk` and `~/.ssh/id_ed25519_sk.pub`). Alternatively, copy the handle directly from the **Handle** button in the app.

### Downloading resident keys

Resident keys can be downloaded to any machine without needing the original handle file:

```bash
ssh-keygen -K -w ./sk/libpocket-sk.so
# Phone shows an Allow/Deny dialog
# Creates ~/.ssh/id_ed25519_sk_rk and ~/.ssh/id_ed25519_sk_rk.pub
```

This is useful when setting up a new machine — just pair the phone and download your keys.

### Using the key

**Option A — per-command flag:**

```bash
ssh -i ~/.ssh/id_ed25519_sk -o SecurityKeyProvider=./sk/libpocket-sk.so user@server
```

**Option B — `~/.ssh/config` (recommended):**

```
Host myserver
    HostName server.example.com
    User myuser
    IdentityFile ~/.ssh/id_ed25519_sk
    SecurityKeyProvider /path/to/libpocket-sk.so
```

Then just:

```bash
ssh myserver   # biometric prompt appears on phone
```

**Option C — system install:**

```bash
cd proxy/sk && sudo make install
# installs to /usr/local/lib/libpocket-sk.so
```

Then in `~/.ssh/config`:

```
SecurityKeyProvider /usr/local/lib/libpocket-sk.so
```

### Using with ssh-agent

Loading the key into `ssh-agent` lets you authenticate without repeating the `-o SecurityKeyProvider` flag on every command. OpenSSH 8.2+ stores the provider path alongside the key in the agent so sign requests are automatically forwarded to the phone.

**Add the key to the running agent:**

```bash
ssh-add -S /path/to/libpocket-sk.so ~/.ssh/id_ed25519_sk
```

The `-S` flag tells the agent which SK provider to call when this key is used for signing. Without it the agent will refuse SK sign requests.

**Verify the key is loaded:**

```bash
ssh-add -l
# 256 SHA256:... ali@phone (ED25519-SK)
```

**Connect — no extra flags needed:**

```bash
ssh user@server   # agent handles the SK signing, biometric prompt appears on phone
```

**Agent forwarding** works as normal; the SK provider is invoked locally even when the agent is forwarded to a remote host:

```bash
ssh -A jumphost
ssh user@internal   # still prompts on your phone
```

**Persistent setup** — add to your shell profile so the key is loaded on login:

```bash
# ~/.bashrc or ~/.zshrc
ssh-add -S /path/to/libpocket-sk.so ~/.ssh/id_ed25519_sk 2>/dev/null
```

### Hardware attestation

ECDSA keys support Android hardware attestation, which cryptographically proves the key lives in the phone's TEE or StrongBox — not in software. The attestation certificate chain is anchored to Google's published hardware attestation roots.

```bash
# Generate an ECDSA key with attestation:
ssh-keygen -t ecdsa-sk -w ./sk/libpocket-sk.so -O write-attestation=key.attest

# Verify the attestation chain:
./pocket-agent verify-attestation key.attest
# Attestation chain (4 certs):
#   [0] subject: ...
# Chain signature linkage: OK
# Chain anchors to Google hardware attestation root: OK
#
# Key Description:
#   KeyMint security level:     StrongBox
#
# → Key is hardware-backed in StrongBox (highest assurance).
```

To verify the challenge matches what ssh-keygen sent:

```bash
./pocket-agent verify-attestation --challenge <hex> key.attest
```

### Diagnostics

```bash
./pocket-agent test
# [1/3] Device keys loaded
# [2/3] BLE connected
# [3/3] Authenticated (AES-256-GCM session established)
```

### Configuration

```
~/.config/pocket-agent/
└── keys/
    ├── device.key   Ed25519 private key (desktop identity for BLE auth)
    └── device.pub   Ed25519 public key
```

Generated automatically on first `pair` run.

## Termux (on-device)

Use PocketKey directly from Termux on the same phone — no desktop or BLE needed. The SK provider communicates with the PocketKey app via Android's ordered broadcast IPC.

### Requirements

- PocketKey app installed
- Termux with Go and OpenSSH: `pkg install golang openssh`

### Build

```bash
cd termux/sk
make
# produces libpocket-sk.so
```

### Creating an SSH key

```bash
ssh-keygen -t ed25519-sk -w ./libpocket-sk.so

# ECDSA
ssh-keygen -t ecdsa-sk -w ./libpocket-sk.so

# Resident key
ssh-keygen -t ed25519-sk -O resident -w ./libpocket-sk.so
```

The PocketKey app will show an **Allow / Deny** dialog. Tap **Allow** to generate the key.

### Downloading resident keys

```bash
ssh-keygen -K -w ./libpocket-sk.so
# Creates ~/.ssh/id_ed25519_sk_rk and ~/.ssh/id_ed25519_sk_rk.pub
```

### Using the key

```bash
ssh -i ~/.ssh/id_ed25519_sk -o SecurityKeyProvider=./libpocket-sk.so user@server
```

Or in `~/.ssh/config`:

```
Host myserver
    HostName server.example.com
    User myuser
    IdentityFile ~/.ssh/id_ed25519_sk
    SecurityKeyProvider /data/data/com.termux/files/home/termux/sk/libpocket-sk.so
```

### Using with ssh-agent

OpenSSH requires explicitly allowing custom SK providers with the `-P` flag:

```bash
eval $(ssh-agent -P /path/to/libpocket-sk.so)
ssh-add -S /path/to/libpocket-sk.so ~/.ssh/id_ed25519_sk
ssh-add -l
# 256 SHA256:... (ED25519-SK)

ssh user@server   # no extra flags needed, biometric prompt appears on screen
```

To persist across sessions, add to `~/.bashrc` or `~/.zshrc`:

```bash
if [ -z "$SSH_AUTH_SOCK" ]; then
    eval $(ssh-agent -P /path/to/libpocket-sk.so)
fi
ssh-add -S /path/to/libpocket-sk.so ~/.ssh/id_ed25519_sk 2>/dev/null
```

### Notes

- The PocketKey app must be open for biometric and enrollment prompts to appear.
- No root, ADB, or Shizuku required — the provider uses `am broadcast` to communicate with the app.

## Security

- **Private keys never leave the phone.** Signing happens inside Android Keystore (StrongBox/TEE); only the signature crosses BLE.
- **Per-sign biometric.** Every SSH authentication requires a fresh fingerprint/face/PIN approval — no caching, no session window.
- **Explicit enrollment confirmation.** The phone shows an Allow/Deny dialog before generating any new key, whether requested locally or by `ssh-keygen`.
- **Mutual authentication.** The desktop must prove its identity with its Ed25519 device key before the phone responds to any request. Only paired devices are trusted.
- **Encrypted transport.** After authentication, all BLE traffic is encrypted with AES-256-GCM using an X25519 ECDH session key.
- **QR pairing with signature verification.** The pairing QR payload is signed by the desktop key; the app verifies the signature before adding the device to its trust store.

## Troubleshooting

**BLE connection fails**

1. Check Bluetooth is on: `bluetoothctl show`
2. Ensure the Android app is open and the service notification is visible
3. Phone must be within BLE range (< ~10 m)
4. Verify pairing: `ls ~/.config/pocket-agent/keys/` — both `device.key` and `device.pub` must exist

Run `./pocket-agent test` for a step-by-step diagnosis.

**ssh-keygen hangs waiting for the phone**

The phone is showing an Allow/Deny dialog. Check the Android screen and tap **Allow** to proceed.

**SSH hangs after connecting**

The phone is waiting for biometric input. Check the Android screen for a fingerprint/face prompt. If no prompt appears, verify the app has notification and biometric permissions in Android Settings.

**New key not appearing in the app**

The key list refreshes automatically. If it doesn't update, close and reopen the app.
