package com.example.pocketsshagent.agent

import android.util.Base64
import android.util.Log
import com.example.pocketsshagent.crypto.KeyManager
import com.example.pocketsshagent.crypto.SessionCrypto
import com.example.pocketsshagent.pairing.TrustStore
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.concurrent.atomic.AtomicBoolean

interface AgentCallback {
    fun requestBiometricSign(alias: String, keyLabel: String, deviceName: String?, data: ByteArray, onResult: (ByteArray?) -> Unit)
}

class SshAgentHandler(
    private val keyManager: KeyManager,
    private val callback: AgentCallback,
    private val trustStore: TrustStore? = null,
    private val signingInProgress: AtomicBoolean = AtomicBoolean(false)
) {
    companion object {
        private const val TAG = "SshAgentHandler"
    }

    private var authenticated = false
    private var authenticatedDeviceKey: String? = null
    private var sessionCrypto: SessionCrypto? = null

    fun resetSession() {
        authenticated = false
        authenticatedDeviceKey = null
        sessionCrypto = null
    }

    fun handleMessage(message: ByteArray, onResponse: (ByteArray) -> Unit) {
        if (message.isEmpty()) {
            onResponse(SshWireFormat.frameMessage(AgentMessageBuilder.failure()))
            return
        }

        // Auth message always arrives in plaintext — it establishes the session key
        if (AgentMessageParser.messageType(message) == AgentMessageType.POCKET_AUTH_REQUEST) {
            handleAuthRequest(message, onResponse)
            return
        }

        // Decrypt incoming message when a session key is active
        val crypto = sessionCrypto
        val plaintext: ByteArray = if (crypto != null) {
            try {
                crypto.open(message)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to decrypt incoming message", e)
                onResponse(SshWireFormat.frameMessage(AgentMessageBuilder.failure()))
                return
            }
        } else {
            message
        }

        if (plaintext.isEmpty()) {
            onResponse(SshWireFormat.frameMessage(AgentMessageBuilder.failure()))
            return
        }

        // Wrap onResponse to encrypt outgoing responses when a session is active.
        // Incoming framed = [4B len][raw]; strip len, encrypt raw, re-frame.
        val respond: (ByteArray) -> Unit = if (crypto != null) { framed ->
            val raw = framed.copyOfRange(4, framed.size)
            val encrypted = try {
                crypto.seal(raw)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to encrypt response", e)
                raw
            }
            onResponse(SshWireFormat.frameMessage(encrypted))
        } else {
            onResponse
        }

        when (AgentMessageParser.messageType(plaintext)) {
            AgentMessageType.SSH_AGENTC_REQUEST_IDENTITIES -> {
                if (!requireAuth(respond)) return
                respond(SshWireFormat.frameMessage(handleRequestIdentities()))
            }
            AgentMessageType.SSH_AGENTC_SIGN_REQUEST -> {
                if (!requireAuth(respond)) return
                handleSignRequest(plaintext, respond)
            }
            else -> respond(SshWireFormat.frameMessage(AgentMessageBuilder.failure()))
        }
    }

    private fun requireAuth(onResponse: (ByteArray) -> Unit): Boolean {
        if (trustStore == null) return true
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

        val verified = try {
            val keySpec = X509EncodedKeySpec(authRequest.publicKey)
            val keyFactory = KeyFactory.getInstance("Ed25519")
            val publicKey = keyFactory.generatePublic(keySpec)
            val sig = Signature.getInstance("Ed25519")
            sig.initVerify(publicKey)
            // Signature covers nonce || x25519EphemeralKey, binding the ephemeral key
            // to the Ed25519 identity to prevent MITM substitution.
            sig.update(authRequest.nonce + authRequest.x25519EphemeralKey)
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

        val publicKeyBase64 = Base64.encodeToString(authRequest.publicKey, Base64.NO_WRAP)
        if (trustStore != null && !trustStore.isTrusted(publicKeyBase64)) {
            Log.w(TAG, "Auth request: device not trusted")
            onResponse(SshWireFormat.frameMessage(AgentMessageBuilder.authFailure()))
            return
        }

        // ECDH key exchange: derive per-session AES-256-GCM key
        val (crypto, ourPubRaw) = try {
            SessionCrypto.establish(authRequest.x25519EphemeralKey, authRequest.nonce)
        } catch (e: Exception) {
            Log.e(TAG, "ECDH key exchange failed", e)
            onResponse(SshWireFormat.frameMessage(AgentMessageBuilder.authFailure()))
            return
        }

        authenticated = true
        authenticatedDeviceKey = publicKeyBase64
        sessionCrypto = crypto
        trustStore?.updateLastSeen(publicKeyBase64)
        Log.i(TAG, "Session authenticated and encrypted (AES-256-GCM) for device: ${publicKeyBase64.take(8)}…")

        // 101 response carries phone's ephemeral X25519 pubkey (plaintext — session starts after this)
        onResponse(SshWireFormat.frameMessage(AgentMessageBuilder.authSuccess(ourPubRaw)))
    }

    private fun handleRequestIdentities(): ByteArray {
        val keys = keyManager.listKeys()
        val keyPairs = keys.mapNotNull { metadata ->
            try {
                val publicKey = keyManager.getPublicKey(metadata.alias)
                val encoded = publicKey.encoded
                val keyBlob = when {
                    SshWireFormat.isEd25519PublicKey(encoded) -> {
                        Log.d(TAG, "Key '${metadata.label}': Ed25519")
                        SshWireFormat.encodeEd25519PublicKey(
                            SshWireFormat.extractRawEd25519PublicKey(encoded)
                        )
                    }
                    SshWireFormat.isP256PublicKey(encoded) -> {
                        Log.d(TAG, "Key '${metadata.label}': ECDSA P-256")
                        SshWireFormat.encodeEcdsaP256PublicKey(
                            SshWireFormat.extractRawP256PublicKey(encoded)
                        )
                    }
                    else -> {
                        Log.w(TAG, "Key '${metadata.label}': unknown type (encodedLen=${encoded.size}), skipping")
                        return@mapNotNull null
                    }
                }
                keyBlob to metadata.label
            } catch (e: Exception) {
                Log.e(TAG, "Failed to load key '${metadata.label}': $e")
                null
            }
        }
        return AgentMessageBuilder.identitiesAnswer(keyPairs)
    }

    private fun handleSignRequest(message: ByteArray, onResponse: (ByteArray) -> Unit) {
        if (!signingInProgress.compareAndSet(false, true)) {
            Log.w(TAG, "Sign request rejected: signing already in progress")
            onResponse(SshWireFormat.frameMessage(AgentMessageBuilder.failure()))
            return
        }

        val signRequest = try {
            AgentMessageParser.parseSignRequest(message)
        } catch (_: Exception) {
            signingInProgress.set(false)
            onResponse(SshWireFormat.frameMessage(AgentMessageBuilder.failure()))
            return
        }

        val (alias, isP256) = findKeyAlias(signRequest.keyBlob) ?: run {
            signingInProgress.set(false)
            onResponse(SshWireFormat.frameMessage(AgentMessageBuilder.failure()))
            return
        }

        val keyLabel = keyManager.listKeys().find { it.alias == alias }?.label ?: alias
        val deviceName = authenticatedDeviceKey?.let { trustStore?.getDevice(it)?.label }

        callback.requestBiometricSign(alias, keyLabel, deviceName, signRequest.data) { signature ->
            signingInProgress.set(false)
            if (signature != null) {
                keyManager.updateLastUsed(alias)
                val response = if (isP256) {
                    AgentMessageBuilder.signResponseEcdsaP256(signature)
                } else {
                    AgentMessageBuilder.signResponseEd25519(signature)
                }
                onResponse(SshWireFormat.frameMessage(response))
            } else {
                onResponse(SshWireFormat.frameMessage(AgentMessageBuilder.failure()))
            }
        }
    }

    /** Returns (alias, isP256) for the key matching the requested blob, or null. */
    private fun findKeyAlias(requestedKeyBlob: ByteArray): Pair<String, Boolean>? {
        for (metadata in keyManager.listKeys()) {
            try {
                val publicKey = keyManager.getPublicKey(metadata.alias)
                val encoded = publicKey.encoded
                val keyBlob = when {
                    SshWireFormat.isEd25519PublicKey(encoded) ->
                        SshWireFormat.encodeEd25519PublicKey(
                            SshWireFormat.extractRawEd25519PublicKey(encoded)
                        )
                    SshWireFormat.isP256PublicKey(encoded) ->
                        SshWireFormat.encodeEcdsaP256PublicKey(
                            SshWireFormat.extractRawP256PublicKey(encoded)
                        )
                    else -> continue
                }
                if (keyBlob.contentEquals(requestedKeyBlob)) {
                    return metadata.alias to SshWireFormat.isP256PublicKey(encoded)
                }
            } catch (_: Exception) {
                continue
            }
        }
        return null
    }
}
