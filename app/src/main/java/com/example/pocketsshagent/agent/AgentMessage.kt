package com.example.pocketsshagent.agent

/**
 * SSH agent protocol constants and message types.
 * Reference: draft-miller-ssh-agent (OpenSSH agent protocol).
 */
object AgentMessageType {
    // Requests (client -> agent)
    const val SSH_AGENTC_REQUEST_IDENTITIES: Byte = 11
    const val SSH_AGENTC_SIGN_REQUEST: Byte = 13

    // Custom: session authentication (proxy -> phone)
    const val POCKET_AUTH_REQUEST: Byte = 100

    // Responses (agent -> client)
    const val SSH_AGENT_FAILURE: Byte = 5
    const val SSH_AGENT_IDENTITIES_ANSWER: Byte = 12
    const val SSH_AGENT_SIGN_RESPONSE: Byte = 14

    // Custom: session authentication responses (phone -> proxy)
    const val POCKET_AUTH_SUCCESS: Byte = 101
    const val POCKET_AUTH_FAILURE: Byte = 102
}

/** Flags for sign request. */
object AgentSignFlags {
    const val SSH_AGENT_RSA_SHA2_256: Int = 2
    const val SSH_AGENT_RSA_SHA2_512: Int = 4
}

/** Parsed sign request from the client. */
data class SignRequest(
    val keyBlob: ByteArray,
    val data: ByteArray,
    val flags: Int
)

/**
 * Parsed auth request from the proxy.
 * Format: byte type | string publicKey (X.509) | string nonce | string signature
 */
data class AuthRequest(
    val publicKey: ByteArray,
    val nonce: ByteArray,
    val signature: ByteArray
)

/** Parse a raw agent message (after length prefix is removed). */
object AgentMessageParser {

    /**
     * Parse the message type byte from a raw agent message.
     */
    fun messageType(message: ByteArray): Byte {
        require(message.isNotEmpty()) { "Empty agent message" }
        return message[0]
    }

    /**
     * Parse a SIGN_REQUEST message body (after the type byte).
     * Format: byte type | string key_blob | string data | uint32 flags
     */
    fun parseSignRequest(message: ByteArray): SignRequest {
        require(message[0] == AgentMessageType.SSH_AGENTC_SIGN_REQUEST) {
            "Not a sign request"
        }
        var offset = 1
        val (keyBlob, nextOffset1) = SshWireFormat.decodeString(message, offset)
        offset = nextOffset1
        val (data, nextOffset2) = SshWireFormat.decodeString(message, offset)
        offset = nextOffset2
        val flags = if (offset + 4 <= message.size) {
            SshWireFormat.decodeUint32(message, offset)
        } else {
            0
        }
        return SignRequest(keyBlob, data, flags)
    }

    /**
     * Parse a POCKET_AUTH_REQUEST message.
     * Format: byte type | string publicKey | string nonce | string signature
     */
    fun parseAuthRequest(message: ByteArray): AuthRequest {
        require(message[0] == AgentMessageType.POCKET_AUTH_REQUEST) {
            "Not an auth request"
        }
        var offset = 1
        val (publicKey, off1) = SshWireFormat.decodeString(message, offset)
        offset = off1
        val (nonce, off2) = SshWireFormat.decodeString(message, offset)
        offset = off2
        val (signature, _) = SshWireFormat.decodeString(message, offset)
        return AuthRequest(publicKey, nonce, signature)
    }
}

/** Build agent response messages. */
object AgentMessageBuilder {

    /** Build SSH_AGENT_FAILURE response. */
    fun failure(): ByteArray = byteArrayOf(AgentMessageType.SSH_AGENT_FAILURE)

    /**
     * Build SSH_AGENT_IDENTITIES_ANSWER response.
     * Format: byte type | uint32 nkeys | (string key_blob | string comment)*
     */
    fun identitiesAnswer(keys: List<Pair<ByteArray, String>>): ByteArray {
        val body = mutableListOf<Byte>()
        body.add(AgentMessageType.SSH_AGENT_IDENTITIES_ANSWER)
        body.addAll(SshWireFormat.encodeUint32(keys.size).toList())
        for ((keyBlob, comment) in keys) {
            body.addAll(SshWireFormat.encodeString(keyBlob).toList())
            body.addAll(SshWireFormat.encodeString(comment).toList())
        }
        return body.toByteArray()
    }

    /**
     * Build SSH_AGENT_SIGN_RESPONSE for Ed25519.
     */
    fun signResponseEd25519(signature: ByteArray): ByteArray {
        val encodedSig = SshWireFormat.encodeEd25519Signature(signature)
        return byteArrayOf(AgentMessageType.SSH_AGENT_SIGN_RESPONSE) +
               SshWireFormat.encodeString(encodedSig)
    }

    /**
     * Build SSH_AGENT_SIGN_RESPONSE for ECDSA P-256.
     * signature: raw DER bytes from Android's NONEwithECDSA.
     */
    fun signResponseEcdsaP256(signature: ByteArray): ByteArray {
        val encodedSig = SshWireFormat.encodeEcdsaP256SignatureFromDer(signature)
        return byteArrayOf(AgentMessageType.SSH_AGENT_SIGN_RESPONSE) +
               SshWireFormat.encodeString(encodedSig)
    }

    /** Build POCKET_AUTH_SUCCESS response. */
    fun authSuccess(): ByteArray = byteArrayOf(AgentMessageType.POCKET_AUTH_SUCCESS)

    /** Build POCKET_AUTH_FAILURE response. */
    fun authFailure(): ByteArray = byteArrayOf(AgentMessageType.POCKET_AUTH_FAILURE)
}
