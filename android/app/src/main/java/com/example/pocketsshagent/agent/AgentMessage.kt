package com.example.pocketsshagent.agent

object AgentMessageType {
    const val SSH_AGENT_FAILURE: Byte = 5

    // Session authentication (proxy <-> phone)
    const val POCKET_AUTH_REQUEST: Byte  = 100
    const val POCKET_AUTH_SUCCESS: Byte  = 101
    const val POCKET_AUTH_FAILURE: Byte  = 102

    // SK (FIDO2-style security key) operations (proxy <-> phone)
    const val SK_ENROLL_REQUEST: Byte  = 103
    const val SK_ENROLL_RESPONSE: Byte = 104
    const val SK_SIGN_REQUEST: Byte    = 105
    const val SK_SIGN_RESPONSE: Byte   = 106

    /**
     * Highest session protocol version this app speaks. Bumped only when the
     * wire format, transcript, or KDF changes. The phone picks
     * min(clientVersion, PROTOCOL_VERSION) during auth and binds the negotiated
     * byte into the HKDF info string for downgrade protection.
     */
    const val PROTOCOL_VERSION: Int = 1
}

/**
 * Parsed SK_ENROLL_REQUEST from the proxy.
 * Format: byte type | byte alg | bytes app_hash[32] | byte flags | uint16 label_len | bytes label
 */
data class SkEnrollRequest(
    val alg: Int,
    val appHash: ByteArray,
    val flags: Byte,
    val label: String = "",
    val attestationChallenge: ByteArray = ByteArray(0)
)

/**
 * Parsed SK_SIGN_REQUEST from the proxy.
 * Format: byte type | uint16 handle_len | bytes handle | bytes app_hash[32] | byte flags | bytes data_hash[32]
 */
data class SkSignRequest(
    val handle: String,
    val appHash: ByteArray,
    val flags: Byte,
    val dataHash: ByteArray
)

/**
 * Parsed POCKET_AUTH_REQUEST from the proxy.
 * Format: byte type | string publicKey | string nonce | string signature | string x25519EphemeralKey | byte clientVersion?
 *
 * The trailing clientVersion byte is optional — older proxies omit it, in which
 * case we default to protocol version 1.
 */
data class AuthRequest(
    val publicKey: ByteArray,
    val nonce: ByteArray,
    val signature: ByteArray,
    val x25519EphemeralKey: ByteArray,
    val clientVersion: Int = 1
)

object AgentMessageParser {

    fun messageType(message: ByteArray): Byte {
        require(message.isNotEmpty()) { "Empty agent message" }
        return message[0]
    }

    fun parseSkEnrollRequest(message: ByteArray): SkEnrollRequest {
        require(message[0] == AgentMessageType.SK_ENROLL_REQUEST) { "Not an SK enroll request" }
        require(message.size >= 35) { "SK enroll request too short: ${message.size}" }
        val alg = message[1].toInt() and 0xFF
        val appHash = message.copyOfRange(2, 34)
        val flags = message[34]
        var label = ""
        var off = 35
        if (message.size >= off + 2) {
            val labelLen = ((message[off].toInt() and 0xFF) shl 8) or (message[off + 1].toInt() and 0xFF)
            off += 2
            if (labelLen > 0 && message.size >= off + labelLen) {
                label = String(message, off, labelLen, Charsets.UTF_8)
                off += labelLen
            } else if (labelLen > 0) {
                // Truncated label — bail, treat rest as absent.
                return SkEnrollRequest(alg, appHash, flags, label)
            }
        }
        var challenge = ByteArray(0)
        if (message.size >= off + 2) {
            val chLen = ((message[off].toInt() and 0xFF) shl 8) or (message[off + 1].toInt() and 0xFF)
            off += 2
            if (chLen > 0 && message.size >= off + chLen) {
                challenge = message.copyOfRange(off, off + chLen)
            }
        }
        return SkEnrollRequest(alg, appHash, flags, label, challenge)
    }

    fun parseSkSignRequest(message: ByteArray): SkSignRequest {
        require(message[0] == AgentMessageType.SK_SIGN_REQUEST) { "Not an SK sign request" }
        require(message.size >= 1 + 2) { "SK sign request too short" }
        val handleLen = ((message[1].toInt() and 0xFF) shl 8) or (message[2].toInt() and 0xFF)
        val minSize = 1 + 2 + handleLen + 32 + 1 + 32
        require(message.size >= minSize) { "SK sign request too short: ${message.size} < $minSize" }
        var offset = 3
        val handle = String(message, offset, handleLen, Charsets.UTF_8); offset += handleLen
        val appHash = message.copyOfRange(offset, offset + 32); offset += 32
        val flags = message[offset]; offset++
        val dataHash = message.copyOfRange(offset, offset + 32)
        return SkSignRequest(handle, appHash, flags, dataHash)
    }

    fun parseAuthRequest(message: ByteArray): AuthRequest {
        require(message[0] == AgentMessageType.POCKET_AUTH_REQUEST) { "Not an auth request" }
        var offset = 1
        val (publicKey, off1) = SshWireFormat.decodeString(message, offset); offset = off1
        val (nonce,     off2) = SshWireFormat.decodeString(message, offset); offset = off2
        val (signature, off3) = SshWireFormat.decodeString(message, offset); offset = off3
        val (x25519Key, off4) = SshWireFormat.decodeString(message, offset); offset = off4
        // Optional trailing version byte. Pre-versioning proxies omit it.
        val clientVersion = if (offset < message.size) message[offset].toInt() and 0xFF else 1
        return AuthRequest(publicKey, nonce, signature, x25519Key, clientVersion)
    }
}

object AgentMessageBuilder {

    fun failure(): ByteArray = byteArrayOf(AgentMessageType.SSH_AGENT_FAILURE)

    /**
     * Build a POCKET_AUTH_SUCCESS response.
     *   byte(101) | string(phoneEphemeralPub) | byte(negotiatedVersion)
     *
     * The trailing version byte is what the phone selected (== min of its own
     * max and the client's max). The client validates this and binds it into
     * the HKDF info string — see [SessionCrypto.establish].
     */
    fun authSuccess(phoneEphemeralPub: ByteArray, negotiatedVersion: Int): ByteArray =
        byteArrayOf(AgentMessageType.POCKET_AUTH_SUCCESS) +
            SshWireFormat.encodeString(phoneEphemeralPub) +
            byteArrayOf((negotiatedVersion and 0xFF).toByte())

    fun authFailure(): ByteArray = byteArrayOf(AgentMessageType.POCKET_AUTH_FAILURE)
}
