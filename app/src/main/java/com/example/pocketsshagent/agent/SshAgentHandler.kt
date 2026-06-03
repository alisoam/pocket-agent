package com.example.pocketsshagent.agent

import android.util.Base64
import android.util.Log
import com.example.pocketsshagent.crypto.KeyManager
import com.example.pocketsshagent.pairing.TrustStore
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

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
 * Requires session authentication before allowing agent operations.
 */
class SshAgentHandler(
    private val keyManager: KeyManager,
    private val callback: AgentCallback,
    private val trustStore: TrustStore? = null
) {
    companion object {
        private const val TAG = "SshAgentHandler"
    }

    // Per-session authentication state
    private var authenticated = false

    /**
     * Reset authentication state (call when a device disconnects).
     */
    fun resetSession() {
        authenticated = false
    }

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
            AgentMessageType.POCKET_AUTH_REQUEST -> {
                handleAuthRequest(message, onResponse)
            }
            AgentMessageType.SSH_AGENTC_REQUEST_IDENTITIES -> {
                if (!requireAuth(onResponse)) return
                val response = handleRequestIdentities()
                onResponse(SshWireFormat.frameMessage(response))
            }
            AgentMessageType.SSH_AGENTC_SIGN_REQUEST -> {
                if (!requireAuth(onResponse)) return
                handleSignRequest(message, onResponse)
            }
            else -> {
                onResponse(SshWireFormat.frameMessage(AgentMessageBuilder.failure()))
            }
        }
    }

    private fun requireAuth(onResponse: (ByteArray) -> Unit): Boolean {
        if (trustStore == null) {
            // No trust store configured — skip auth (backwards compatible)
            return true
        }
        if (!authenticated) {
            Log.w(TAG, "Rejecting request: session not authenticated")
            onResponse(SshWireFormat.frameMessage(AgentMessageBuilder.authFailure()))
            return false
        }
        return true
    }

    private fun handleAuthRequest(message: ByteArray, onResponse: (ByteArray) -> Unit) {
        val authRequest = try {
            AgentMessageParser.parseAuthRequest(message)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to parse auth request", e)
            onResponse(SshWireFormat.frameMessage(AgentMessageBuilder.authFailure()))
            return
        }

        // Verify signature over nonce using the provided public key
        val verified = try {
            val keySpec = X509EncodedKeySpec(authRequest.publicKey)
            val keyFactory = KeyFactory.getInstance("Ed25519")
            val publicKey = keyFactory.generatePublic(keySpec)
            val sig = Signature.getInstance("Ed25519")
            sig.initVerify(publicKey)
            sig.update(authRequest.nonce)
            sig.verify(authRequest.signature)
        } catch (e: Exception) {
            Log.e(TAG, "Auth signature verification failed", e)
            false
        }

        if (!verified) {
            Log.w(TAG, "Auth request: invalid signature")
            onResponse(SshWireFormat.frameMessage(AgentMessageBuilder.authFailure()))
            return
        }

        // Check if this public key is in the trust store
        val publicKeyBase64 = Base64.encodeToString(authRequest.publicKey, Base64.NO_WRAP)
        if (trustStore != null && !trustStore.isTrusted(publicKeyBase64)) {
            Log.w(TAG, "Auth request: device not trusted (may have been removed)")
            onResponse(SshWireFormat.frameMessage(AgentMessageBuilder.authFailure()))
            return
        }

        // Authentication successful
        authenticated = true
        trustStore?.updateLastSeen(publicKeyBase64)
        Log.i(TAG, "Session authenticated for device: $publicKeyBase64")
        onResponse(SshWireFormat.frameMessage(AgentMessageBuilder.authSuccess()))
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
