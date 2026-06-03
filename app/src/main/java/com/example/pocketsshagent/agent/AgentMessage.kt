package com.example.pocketsshagent.agent

/**
 * SSH agent protocol constants and message types.
 * Reference: draft-miller-ssh-agent (OpenSSH agent protocol).
 */
object AgentMessageType {
    // Requests (client -> agent)
    const val SSH_AGENTC_REQUEST_IDENTITIES: Byte = 11
    const val SSH_AGENTC_SIGN_REQUEST: Byte = 13

    // Responses (agent -> client)
    const val SSH_AGENT_FAILURE: Byte = 5
    const val SSH_AGENT_IDENTITIES_ANSWER: Byte = 12
    const val SSH_AGENT_SIGN_RESPONSE: Byte = 14
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
     * Build SSH_AGENT_SIGN_RESPONSE.
     * Format: byte type | string signature
     */
    fun signResponse(signature: ByteArray): ByteArray {
        val body = mutableListOf<Byte>()
        body.add(AgentMessageType.SSH_AGENT_SIGN_RESPONSE)
        // The signature is wrapped in an SSH string containing the encoded signature blob
        val encodedSig = SshWireFormat.encodeEd25519Signature(signature)
        body.addAll(SshWireFormat.encodeString(encodedSig).toList())
        return body.toByteArray()
    }
}
