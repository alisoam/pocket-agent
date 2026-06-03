package com.example.pocketsshagent.agent

import com.example.pocketsshagent.crypto.KeyManager
import java.security.PublicKey

/**
 * Callback interface for operations requiring user interaction.
 */
interface AgentCallback {
    /**
     * Called when a sign request requires biometric approval.
     * The implementation should prompt the user and call [onResult] with the
     * signature bytes on approval, or null on denial/failure.
     *
     * @param alias The key alias to sign with.
     * @param data The data to be signed.
     * @param onResult Callback with signature bytes or null.
     */
    fun requestBiometricSign(alias: String, data: ByteArray, onResult: (ByteArray?) -> Unit)
}

/**
 * Core SSH agent protocol handler.
 * Processes incoming agent messages and produces responses.
 */
class SshAgentHandler(
    private val keyManager: KeyManager,
    private val callback: AgentCallback
) {

    /**
     * Process a raw agent message (without length prefix).
     * Calls [onResponse] with the framed response message.
     *
     * Note: This is async because SIGN_REQUEST requires biometric approval.
     */
    fun handleMessage(message: ByteArray, onResponse: (ByteArray) -> Unit) {
        if (message.isEmpty()) {
            onResponse(SshWireFormat.frameMessage(AgentMessageBuilder.failure()))
            return
        }

        when (AgentMessageParser.messageType(message)) {
            AgentMessageType.SSH_AGENTC_REQUEST_IDENTITIES -> {
                val response = handleRequestIdentities()
                onResponse(SshWireFormat.frameMessage(response))
            }
            AgentMessageType.SSH_AGENTC_SIGN_REQUEST -> {
                handleSignRequest(message, onResponse)
            }
            else -> {
                onResponse(SshWireFormat.frameMessage(AgentMessageBuilder.failure()))
            }
        }
    }

    private fun handleRequestIdentities(): ByteArray {
        val keys = keyManager.listKeys()
        val keyPairs = keys.mapNotNull { metadata ->
            try {
                val publicKey = keyManager.getPublicKey(metadata.alias)
                val rawKey = SshWireFormat.extractRawEd25519PublicKey(publicKey.encoded)
                val keyBlob = SshWireFormat.encodeEd25519PublicKey(rawKey)
                val comment = metadata.label
                keyBlob to comment
            } catch (_: Exception) {
                null
            }
        }
        return AgentMessageBuilder.identitiesAnswer(keyPairs)
    }

    private fun handleSignRequest(message: ByteArray, onResponse: (ByteArray) -> Unit) {
        val signRequest = try {
            AgentMessageParser.parseSignRequest(message)
        } catch (_: Exception) {
            onResponse(SshWireFormat.frameMessage(AgentMessageBuilder.failure()))
            return
        }

        // Find the key alias matching the requested key blob
        val alias = findKeyAlias(signRequest.keyBlob)
        if (alias == null) {
            onResponse(SshWireFormat.frameMessage(AgentMessageBuilder.failure()))
            return
        }

        // Request biometric approval and signing
        callback.requestBiometricSign(alias, signRequest.data) { signature ->
            if (signature != null) {
                keyManager.updateLastUsed(alias)
                onResponse(SshWireFormat.frameMessage(AgentMessageBuilder.signResponse(signature)))
            } else {
                onResponse(SshWireFormat.frameMessage(AgentMessageBuilder.failure()))
            }
        }
    }

    /**
     * Find the key alias whose public key blob matches the requested blob.
     */
    private fun findKeyAlias(requestedKeyBlob: ByteArray): String? {
        val keys = keyManager.listKeys()
        for (metadata in keys) {
            try {
                val publicKey = keyManager.getPublicKey(metadata.alias)
                val rawKey = SshWireFormat.extractRawEd25519PublicKey(publicKey.encoded)
                val keyBlob = SshWireFormat.encodeEd25519PublicKey(rawKey)
                if (keyBlob.contentEquals(requestedKeyBlob)) {
                    return metadata.alias
                }
            } catch (_: Exception) {
                continue
            }
        }
        return null
    }
}
