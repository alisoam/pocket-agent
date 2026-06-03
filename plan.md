# Remote SSH agent app for phones

**Session ID:** ses_1734fe285ffemBsjUJGcC483NQ
**Created:** 6/3/2026, 12:23:32 PM
**Updated:** 6/3/2026, 12:28:38 PM

---

## User

I want to make this app to be remote ssh agent on phones. at first it should contains a way to generate ssh keys in android secure chip. and provide a way to manage them guid me to make a plan for this app.

---

## Assistant (Plan · GPT-5.2 Codex · 14.4s)

_Thinking:_



Got it. Here’s a concise, execution‑ready plan for a mobile remote SSH agent app, plus a few key questions to lock scope and security requirements.

**Plan**

- Define scope and threat model  
  - Clarify supported servers/clients, transport (Bluetooth/Wi‑Fi/USB), and trust boundaries.  
  - Decide whether the phone acts as an SSH agent for a separate device (e.g., laptop) or includes its own SSH client.

- Choose key storage strategy  
  - Use Android Keystore with StrongBox/TEE for private key material.  
  - Decide key types (Ed25519 vs RSA vs ECDSA), export policies, and whether to permit external backup of private keys (usually no).

- Design key lifecycle and UX  
  - Key generation flow (name, type, size, comment, StrongBox availability).  
  - Key list + status (hardware‑backed, created time, last used).  
  - Key actions: view public key, rename, delete, revoke, set usage constraints.

- Design agent protocol and transport  
  - Implement SSH agent protocol subset (signing requests, key listing, confirmation prompts).  
  - Pick transport: local socket for on‑device use; for remote devices consider BLE, TCP with TLS + pairing, or USB.  
  - Pairing flow: QR code or passkey, device trust list, per‑host approval.

- Build security controls  
  - Require biometric/PIN for signing or high‑risk operations.  
  - User presence confirmation per signing request (configurable).  
  - Logging and audit: minimal metadata, opt‑in.

- Implement core components (Android + Compose)  
  - Keystore manager: create, list, delete keys; map aliases to user metadata.  
  - Agent service: foreground service handling agent requests and user prompts.  
  - UI: key list, key detail, public key export, connection/pairing screen.  
  - Background safety: handle app lifecycle, service persistence, battery limits.

- Testing and validation  
  - Unit tests for key management and protocol parsing.  
  - Integration tests with OpenSSH client using a test harness.  
  - Device matrix: StrongBox vs non‑StrongBox devices.

- Docs and onboarding  
  - Provide a “How to connect” guide and a sample SSH config snippet.  
  - Explain hardware‑backed limitations and key export policy.

**Questions to finalize the plan**

1) Do you want the phone to act as an agent for a separate machine (e.g., laptop), or only as an on‑device SSH client?  
2) Which transport do you prefer for remote use: Bluetooth, Wi‑Fi TCP, or USB?  
3) Any hard requirement on key type (Ed25519 vs RSA)?  
4) Should every signing request require biometric approval, or only first‑time/unknown hosts?

If you answer these, I can refine the plan into a concrete architecture and milestone breakdown.

---

## User

1. it should act as ssh agent for other devices. 2. (using ble or maybe wifi). 3. I want it to support Ed25519. it should be integrated with device fingerprint (or pin face biometrics). 4. yes every request require bitometric approval (

---

## Assistant (Plan · GPT-5.2 Codex · 15.7s)

_Thinking:_

**Outlining refined plan with clarifying questions**

I will create a concise implementation plan with clear milestones and ask key questions about transport type, pairing mechanisms, and keepalive preferences to tailor the approach effectively.

Great, thanks. Here’s a refined, execution‑ready plan aligned with your decisions: remote SSH agent for other devices, BLE/Wi‑Fi transport, Ed25519, biometric approval for every request.

**Plan**

**1) Architecture & Threat Model**
- Goal: Phone acts as SSH agent for external devices; private keys never leave Android Keystore.
- Threat model: prevent MITM on transport; require explicit pairing and user presence per signature.
- Decide which transports to ship first (BLE, Wi‑Fi, or both).

**2) Cryptography & Key Storage**
- Use Android Keystore (StrongBox/TEE when available) with Ed25519 keys.
- Store key metadata in app DB: alias, label, creation time, usage stats, StrongBox flag.
- Enforce biometric authentication for every signing operation via `BiometricPrompt` (require confirmation).

**3) Agent Protocol Support**
- Implement minimal OpenSSH agent protocol: list keys, sign request, return public key.
- Reject any operation not explicitly supported; no key export of private material.
- Provide key comments and fingerprint display.

**4) Transport & Pairing**
- BLE transport:
  - GATT service with secure characteristics.
  - Pairing via QR/passcode and BLE bonding; store peer identity.
- Wi‑Fi transport:
  - Local TCP server with TLS (self‑signed + TOFU or QR‑shared cert).
  - Optional mDNS discovery.
- Session policy:
  - Per‑request biometric approval.
  - Per‑device trust list with revoke support.

**5) UX & App Flows (Compose)**
- Key list: create, rename, delete, view public key + fingerprint.
- Key creation: Ed25519 only; show hardware‑backed status.
- Pairing screen: add/remove device, show last seen, transport type.
- Request prompt: show requesting device + host + key + purpose; approve/deny.

**6) Background Service & Reliability**
- Foreground service to keep agent active (BLE/TCP).
- Handle app lifecycle, connectivity changes, Doze/battery limits.

**7) Testing & Validation**
- Unit tests: protocol parsing, keystore operations.
- Integration: use OpenSSH client on desktop to validate handshake and signing.
- Device coverage: StrongBox vs non‑StrongBox.

**8) Security & Compliance**
- Logging: minimal, opt‑in.
- Protect metadata with encrypted storage.
- Clear in‑app warnings about trust and pairing.

---

**Milestones**
1) Key management: Ed25519 generation + list + public key export UI.  
2) Biometric‑gated signing flow using Keystore key.  
3) Implement agent protocol core and local test harness.  
4) Transport #1 (BLE or Wi‑Fi) + pairing + trust store.  
5) Full end‑to‑end validation with OpenSSH.  
6) Polish UX and error handling.

---

**Questions to finalize implementation**
1) Which transport should be MVP: BLE first or Wi‑Fi first?  
2) For Wi‑Fi, do you prefer mDNS discovery, or manual IP entry only?  
3) Should pairing be QR‑based, numeric passcode, or both?  
4) Do you want session timeouts (e.g., unlock for 60 seconds) or strict “biometric every request” only?

Once you answer these, I can provide a detailed technical architecture and step‑by‑step implementation checklist tailored to your MVP.

---

## User

1. First BLE 2. ignore Wi-Fi yet. Yes QR-based would be best. 4. strict biometric.

---

## Assistant (Plan · GPT-5.2 Codex · 29.8s)

_Thinking:_

**Planning strict BLE+QR+biometric auth**

I'm outlining a detailed plan combining BLE with QR pairing and strict per-use biometric authentication. The plan covers architecture, protocols (suggesting OpenSSH-agent style), BLE GATT design, QR payload format for pairing, key generation using Android Keystore Ed25519 (min SDK 28 support confirmed), enforcing per-operation biometric prompts with user authentication validity set to 0, and service structure. I'll include recommended stacks and libraries and highlight the need for a desktop-side agent proxy communicating over BLE with the mobile agent. Next, I'll ask to confirm the agent protocol and desktop helper requirements before implementation.

Great, we can lock this to BLE‑only + QR pairing + strict biometric per signing. Here’s a concrete, step‑by‑step plan you can execute.

**Plan**

**1) Core architecture**
- Phone = SSH agent server (stores keys, signs requests).
- Desktop/laptop = SSH agent client/proxy (connects over BLE, speaks SSH agent protocol locally to ssh).
- Transport: BLE GATT with a single “Agent Service” and two characteristics (Rx/Tx).

**2) Key storage & biometric policy**
- Generate Ed25519 keys in Android Keystore (StrongBox/TEE when available).
- Key options:
  - `KeyProperties.KEY_ALGORITHM_ED25519`
  - `setUserAuthenticationRequired(true)`
  - `setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG | DEVICE_CREDENTIAL)`
  - `setUnlockedDeviceRequired(true)` (optional, if you want device‑unlock requirement)
- Every signature operation triggers `BiometricPrompt` with explicit user confirmation.

**3) SSH agent protocol support (minimal)**
- Implement subset of OpenSSH agent protocol:
  - `REQUEST_IDENTITIES` → list public keys + comments.
  - `SIGN_REQUEST` → biometric prompt → sign → return signature.
- Reject everything else; no private key export.

**4) BLE transport & QR pairing**
- BLE GATT service:
  - `Agent Service UUID`
  - `Agent Rx` (write/without response)
  - `Agent Tx` (notify)
- Framing:
  - Use length‑prefixed frames for the SSH agent messages (fits agent protocol).
  - Chunk/reassemble across BLE MTU.
- Pairing via QR:
  - Desktop generates ephemeral keypair + nonce.
  - QR contains: desktop public key, nonce, app‑generated pairing ID, BLE device ID.
  - Phone scans QR, starts BLE connection, verifies desktop proof (signed nonce).
- Trust store:
  - Store trusted desktop public keys + label.
  - Allow revoke from UI.

**5) App UI flows (Compose)**
- Key list screen: label, fingerprint, hardware‑backed status, last used.
- Key creation: Ed25519 only (for now), requires biometric.
- Key detail: show public key, rename, delete, revoke per‑device access.
- Pairing screen: scan QR, list trusted devices, remove device.
- Signing prompt: show desktop device + key + host + purpose; approve/deny.

**6) Background service**
- Foreground service for BLE connections and agent requests.
- Show ongoing notification (“SSH agent active”).
- Robust reconnection handling.

**7) Desktop companion (required)**
- A small agent proxy that:
  - Connects to phone over BLE.
  - Exposes a local SSH agent socket to the OS (`SSH_AUTH_SOCK`).
  - Translates OpenSSH agent protocol <-> BLE transport.
- Target OS choice determines implementation (Go/Rust/Python).

**8) Testing**
- Unit tests: key generation, agent protocol parsing, BLE framing.
- Integration: use `ssh-add -L`, `ssh -v` with the proxy.
- Device matrix: StrongBox vs non‑StrongBox, biometric availability.

---

**Milestones**
1) Key management UI + Ed25519 Keystore generation + public key export.  
2) Biometric‑gated signing of test data.  
3) Agent protocol core (list + sign).  
4) BLE transport with framing + test harness.  
5) QR pairing + trust store.  
6) Desktop proxy + end‑to‑end SSH validation.

---

**Decisions still needed (targeted)**
1) Which desktop OS should the proxy support first (Linux/macOS/Windows)?  
2) What language do you prefer for the desktop proxy (Go, Rust, Python)?

Once you answer those two, I’ll draft a detailed technical architecture plus a task‑by‑task checklist for the MVP.

---

## User

1. Linux 2. Go

---

## Assistant (Plan · GPT-5.2 Codex · 27.4s)

_Thinking:_

**Planning Android app with Go proxy**

I'm outlining a detailed plan including architecture, development milestones, key implementation steps, and risk considerations for building the Android app alongside the Go proxy. I'll specify component interactions and phases but hold off on coding or modifications until confirming any needed read access or other prerequisites.

Great — BLE‑only, QR pairing, strict biometric per request, Linux proxy in Go. Below is a concrete, execution‑ready plan that stays within those constraints and is organized so you can start implementing immediately.

**Plan**

**A) System Architecture**
- Phone (Android) = SSH agent server (keys live in Keystore; signs on demand).
- Linux desktop = SSH agent proxy (connects over BLE, exposes `SSH_AUTH_SOCK`).
- Transport = BLE GATT with framing for SSH agent messages.
- Pairing = QR‑based trust bootstrap + device trust store.

**B) Protocol & Transport Design**
- **Agent protocol subset**
  - `REQUEST_IDENTITIES` → list public keys + comments.
  - `SIGN_REQUEST` → biometric prompt → signature response.
  - Reject any other message types.
- **BLE GATT**
  - Service UUID: `SSH_AGENT_SERVICE`
  - RX Characteristic (Write/WriteWithoutResponse)
  - TX Characteristic (Notify)
  - Framing: 4‑byte length prefix, then payload (OpenSSH agent format)
  - Chunking: split frames into BLE MTU‑sized pieces; reassemble at receiver.
- **Session**
  - No long‑lived auth; every sign triggers biometric.
  - Per‑device trust list gates access to agent operations.

**C) Android App Workstream**
1) **Key Management**
   - Use Android Keystore Ed25519 keys.
   - Store metadata (label, alias, createdAt, hardware‑backed flag, lastUsed) in local DB.
2) **Biometric Signing**
   - Wrap Keystore signing with `BiometricPrompt`.
   - Require authentication for each `SIGN_REQUEST`.
3) **BLE Service**
   - Foreground service + BLE GATT server.
   - Implement framing and flow control.
4) **Pairing (QR)**
   - App scans QR payload from desktop proxy.
   - Verify desktop proof and bind its public key to trust store.
5) **UI (Compose)**
   - Key list, key detail, public key export.
   - Pairing screen (scan/add/remove device).
   - Signing prompt screen with device + key + host info.

**D) Linux Go Proxy Workstream**
1) **Agent Socket**
   - Implement SSH agent protocol server on `SSH_AUTH_SOCK`.
2) **BLE Client**
   - Connect to phone’s GATT service.
   - Handle framing and reassembly.
3) **Pairing UX**
   - Generate device keypair + nonce.
   - Display QR for pairing.
4) **Config & Trust**
   - Store phone’s trusted pairing + labels.
5) **Diagnostics**
   - CLI logs (connection status, agent requests).

**E) Security Model**
- Private keys never leave Keystore.
- Strict biometric per signing request.
- Trust store for paired devices.
- Optional: device‑unlock requirement for signing.

**F) Milestones**
1) Android: Ed25519 key generation + list + export public key.
2) Android: biometric‑gated signing for test messages.
3) Agent protocol core (list + sign) end‑to‑end on device.
4) BLE framing + GATT service + unit tests.
5) Pairing via QR + trust store.
6) Go proxy + local `SSH_AUTH_SOCK` integration.
7) End‑to‑end validation: `ssh-add -L`, `ssh -v`, real server.

**G) Test Strategy**
- Unit tests for protocol parsing and BLE framing.
- Integration tests on Linux using real `ssh` client.
- Device coverage: StrongBox vs non‑StrongBox.

---

**Open questions (only if you want to refine further)**
1) Should the app allow multiple keys per paired device or restrict to selected keys?  
2) Do you want a “view public key as QR” feature to ease adding to servers?  
3) Should the proxy auto‑reconnect or require explicit connect each time?

If you want, I can turn this into a detailed engineering checklist with specific class/module breakdowns for both Android and Go.

---

