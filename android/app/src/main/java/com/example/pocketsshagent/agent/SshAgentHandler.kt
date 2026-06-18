package com.example.pocketsshagent.agent

import android.util.Base64
import android.util.Log
import com.example.pocketsshagent.crypto.KeyManager
import com.example.pocketsshagent.crypto.SessionCrypto
import com.example.pocketsshagent.pairing.TrustStore
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.concurrent.atomic.AtomicBoolean

interface AgentCallback {
    fun requestBiometricSign(alias: String, keyLabel: String, deviceName: String?, data: ByteArray, onResult: (ByteArray?) -> Unit)
    fun requestEnrollConfirmation(label: String, alg: String, deviceName: String?, onResult: (Boolean) -> Unit)
    fun requestResidentKeysAccess(count: Int, deviceName: String?, onResult: (Boolean) -> Unit) {
        onResult(true)
    }
}

class SshAgentHandler(
    private val keyManager: KeyManager,
    private val callback: AgentCallback,
    private val trustStore: TrustStore? = null,
    private val operationInProgress: AtomicBoolean = AtomicBoolean(false)
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
        operationInProgress.set(false)
    }

    fun forceLocalAuth() {
        authenticated = true
        authenticatedDeviceKey = null
        sessionCrypto = null
    }

    fun handleMessage(message: ByteArray, onResponse: (ByteArray) -> Unit) {
        if (message.isEmpty()) {
            onResponse(SshWireFormat.frameMessage(AgentMessageBuilder.failure()))
            return
        }

        if (AgentMessageParser.messageType(message) == AgentMessageType.POCKET_AUTH_REQUEST) {
            handleAuthRequest(message, onResponse)
            return
        }

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
            AgentMessageType.SK_ENROLL_REQUEST -> {
                if (!requireAuth(respond)) return
                handleSkEnroll(plaintext, respond)
            }
            AgentMessageType.SK_SIGN_REQUEST -> {
                if (!requireAuth(respond)) return
                handleSkSign(plaintext, respond)
            }
            AgentMessageType.SK_LOAD_RESIDENT_REQUEST -> {
                if (!requireAuth(respond)) return
                handleSkLoadResident(respond)
            }
            else -> respond(SshWireFormat.frameMessage(AgentMessageBuilder.failure()))
        }
    }

    private fun requireAuth(onResponse: (ByteArray) -> Unit): Boolean {
        if (!authenticated) {
            Log.w(TAG, "Rejecting request: session not authenticated")
            onResponse(SshWireFormat.frameMessage(AgentMessageBuilder.authFailure()))
            return false
        }
        return true
    }

    private fun handleAuthRequest(message: ByteArray, onResponse: (ByteArray) -> Unit) {
        if (authenticated) {
            Log.i(TAG, "Auth request while session active — resetting for new connection")
            resetSession()
        }

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

        // Negotiate protocol version: pick the highest we both support. A version
        // of 0 from the peer is malformed; reject rather than fall through to a
        // weaker default that could be attacker-chosen.
        if (authRequest.clientVersion <= 0) {
            Log.w(TAG, "Auth request: invalid client version ${authRequest.clientVersion}")
            onResponse(SshWireFormat.frameMessage(AgentMessageBuilder.authFailure()))
            return
        }
        val negotiatedVersion = minOf(authRequest.clientVersion, AgentMessageType.PROTOCOL_VERSION)

        val (crypto, ourPubRaw) = try {
            SessionCrypto.establish(authRequest.x25519EphemeralKey, authRequest.nonce, negotiatedVersion)
        } catch (e: Exception) {
            Log.e(TAG, "ECDH key exchange failed", e)
            onResponse(SshWireFormat.frameMessage(AgentMessageBuilder.authFailure()))
            return
        }

        authenticated = true
        authenticatedDeviceKey = publicKeyBase64
        sessionCrypto = crypto
        trustStore?.updateLastSeen(publicKeyBase64)
        Log.i(TAG, "Session authenticated and encrypted (AES-256-GCM, protocol v$negotiatedVersion) for device: ${publicKeyBase64.take(8)}…")

        onResponse(SshWireFormat.frameMessage(AgentMessageBuilder.authSuccess(ourPubRaw, negotiatedVersion)))
    }

    /**
     * SK_ENROLL_REQUEST: generate a new key and return its public key + alias as handle.
     *
     * After generation, the actual key algorithm is verified against the request.
     * If there is a mismatch (device silently fell back to ECDSA when Ed25519 was
     * requested), the key is deleted and a failure is returned — the user must
     * use ssh-keygen -t ecdsa-sk instead.
     *
     * Request:  [type:1=103][alg:1][app_hash:32][flags:1][label_len:2][label:N][chal_len:2][challenge:N]
     * Response: [type:1=104][actual_alg:1][pubkey_len:2][pubkey:N][handle_len:2][handle:N]
     *           [cert_count:1] {[cert_len:2][cert:N]}*
     *
     * The challenge enables Android Keystore hardware attestation: when present and non-empty
     * and the algorithm is ECDSA (alg=0), the returned cert_count is the length of the
     * hardware attestation chain (leaf-first). For Ed25519 or absent challenge, cert_count=0.
     */
    private fun handleSkEnroll(message: ByteArray, onResponse: (ByteArray) -> Unit) {
        if (!operationInProgress.compareAndSet(false, true)) {
            Log.w(TAG, "SK enroll: rejected — enroll already in progress")
            onResponse(SshWireFormat.frameMessage(AgentMessageBuilder.failure()))
            return
        }

        val req = try {
            AgentMessageParser.parseSkEnrollRequest(message)
        } catch (e: Exception) {
            operationInProgress.set(false)
            Log.e(TAG, "SK enroll: parse failed: $e")
            onResponse(SshWireFormat.frameMessage(AgentMessageBuilder.failure()))
            return
        }

        val isEcdsa = req.alg == 0
        if (req.alg != 0 && req.alg != 1) {
            operationInProgress.set(false)
            Log.w(TAG, "SK enroll: unsupported algorithm ${req.alg}")
            onResponse(SshWireFormat.frameMessage(AgentMessageBuilder.failure()))
            return
        }

        val defaultLabel = if (isEcdsa) "Security Key (ecdsa-sk)" else "Security Key (ed25519-sk)"
        val label = req.label.ifEmpty { defaultLabel }
        val algName = if (isEcdsa) "ecdsa-sk" else "ed25519-sk"
        val deviceName = authenticatedDeviceKey?.let { trustStore?.getDevice(it)?.label }

        callback.requestEnrollConfirmation(label, algName, deviceName) { accepted ->
            operationInProgress.set(false)
            if (!accepted) {
                Log.i(TAG, "SK enroll: user rejected key creation for '$label'")
                onResponse(SshWireFormat.frameMessage(AgentMessageBuilder.failure()))
                return@requestEnrollConfirmation
            }
            doEnroll(req, label, isEcdsa, onResponse)
        }
    }

    private fun doEnroll(req: SkEnrollRequest, label: String, isEcdsa: Boolean, onResponse: (ByteArray) -> Unit) {
        // Attestation is only available for EC keys on Android Keystore.
        val challenge = if (isEcdsa && req.attestationChallenge.isNotEmpty()) req.attestationChallenge else null
        val resident = (req.flags.toInt() and 0x20) != 0
        val metadata = try {
            keyManager.generateKey(label, isEcdsa, challenge, resident)
        } catch (e: Exception) {
            Log.e(TAG, "SK enroll: key generation failed: $e")
            onResponse(SshWireFormat.frameMessage(AgentMessageBuilder.failure()))
            return
        }

        // Verify the device actually generated the requested algorithm.
        val actualAlgorithm = keyManager.getKeyAlgorithm(metadata.alias)
        val actualAlg = when (actualAlgorithm) {
            "EC" -> 0
            else -> 1  // Ed25519 / EdDSA
        }

        if (actualAlg != req.alg) {
            Log.w(TAG, "SK enroll: alg mismatch — requested ${req.alg} but device generated $actualAlg ($actualAlgorithm). Deleting key.")
            keyManager.deleteKey(metadata.alias)
            onResponse(SshWireFormat.frameMessage(AgentMessageBuilder.failure()))
            return
        }

        val rawPubKey = try {
            val encoded = keyManager.getPublicKey(metadata.alias).encoded
            if (isEcdsa) SshWireFormat.extractRawP256PublicKey(encoded)
            else SshWireFormat.extractRawEd25519PublicKey(encoded)
        } catch (e: Exception) {
            Log.e(TAG, "SK enroll: failed to extract public key: $e")
            keyManager.deleteKey(metadata.alias)
            onResponse(SshWireFormat.frameMessage(AgentMessageBuilder.failure()))
            return
        }

        // Collect the attestation chain when a challenge was supplied. For non-EC keys or
        // when the device does not support attestation, this returns the (useless) single
        // self-signed cert — we suppress that case to keep cert_count truthful.
        val attestationChain: List<ByteArray> = if (challenge != null) {
            try {
                keyManager.getAttestationChain(metadata.alias)
            } catch (e: Exception) {
                Log.w(TAG, "SK enroll: failed to fetch attestation chain: $e")
                emptyList()
            }
        } else emptyList()

        if (attestationChain.size > 255) {
            Log.w(TAG, "SK enroll: attestation chain longer than 255 certs, truncating")
        }
        val chain = attestationChain.take(255)
        val chainBytes = chain.sumOf { 2 + it.size }

        // Response: [type:1][actual_alg:1][pubkey_len:2][pubkey:N][handle_len:2][handle:N]
        //           [cert_count:1] {[cert_len:2][cert:N]}*
        val handleBytes = metadata.alias.toByteArray(Charsets.UTF_8)
        val response = ByteArray(1 + 1 + 2 + rawPubKey.size + 2 + handleBytes.size + 1 + chainBytes)
        var off = 0
        response[off++] = AgentMessageType.SK_ENROLL_RESPONSE
        response[off++] = actualAlg.toByte()
        response[off++] = (rawPubKey.size shr 8).toByte()
        response[off++] = (rawPubKey.size and 0xFF).toByte()
        System.arraycopy(rawPubKey, 0, response, off, rawPubKey.size); off += rawPubKey.size
        response[off++] = (handleBytes.size shr 8).toByte()
        response[off++] = (handleBytes.size and 0xFF).toByte()
        System.arraycopy(handleBytes, 0, response, off, handleBytes.size); off += handleBytes.size
        response[off++] = chain.size.toByte()
        for (cert in chain) {
            response[off++] = (cert.size shr 8).toByte()
            response[off++] = (cert.size and 0xFF).toByte()
            System.arraycopy(cert, 0, response, off, cert.size); off += cert.size
        }

        Log.i(TAG, "SK enroll succeeded: alg=$actualAlg alias=${metadata.alias} attestationCerts=${chain.size}")
        onResponse(SshWireFormat.frameMessage(response))
    }

    /**
     * SK_SIGN_REQUEST: sign the FIDO2 input for the key identified by handle.
     *
     * The proxy sends pre-hashed components; we embed the counter and sign:
     *   FIDO2 input = app_hash[32] || flags[1] || counter_BE32[4] || data_hash[32] (69 bytes)
     *
     * For Ed25519: sign the 69 bytes directly.
     * For ECDSA P-256: sign SHA-256(69 bytes) via NONEwithECDSA.
     *
     * Request:  [type:1=105][handle_len:2][handle:N][app_hash:32][flags:1][data_hash:32]
     * Response: [type:1=106][sig:64][counter:4][flags:1]
     *   Ed25519: sig[0:64] = full signature
     *   ECDSA:   sig[0:32] = R, sig[32:64] = S
     */
    private fun handleSkSign(message: ByteArray, onResponse: (ByteArray) -> Unit) {
        if (!operationInProgress.compareAndSet(false, true)) {
            Log.w(TAG, "SK sign: rejected — signing already in progress")
            onResponse(SshWireFormat.frameMessage(AgentMessageBuilder.failure()))
            return
        }

        val req = try {
            AgentMessageParser.parseSkSignRequest(message)
        } catch (e: Exception) {
            operationInProgress.set(false)
            Log.e(TAG, "SK sign: parse failed: $e")
            onResponse(SshWireFormat.frameMessage(AgentMessageBuilder.failure()))
            return
        }

        if (keyManager.listKeys().none { it.alias == req.handle }) {
            operationInProgress.set(false)
            Log.w(TAG, "SK sign: unknown key handle: ${req.handle}")
            onResponse(SshWireFormat.frameMessage(AgentMessageBuilder.failure()))
            return
        }

        val counter = keyManager.incrementSkCounter(req.handle)

        // FIDO2 signing input: app_hash || flags || counter_BE32 || data_hash (69 bytes)
        val signingInput = ByteArray(69)
        System.arraycopy(req.appHash, 0, signingInput, 0, 32)
        signingInput[32] = req.flags
        signingInput[33] = (counter shr 24).toByte()
        signingInput[34] = (counter shr 16).toByte()
        signingInput[35] = (counter shr 8).toByte()
        signingInput[36] = counter.toByte()
        System.arraycopy(req.dataHash, 0, signingInput, 37, 32)

        val isEcdsa = keyManager.getKeyAlgorithm(req.handle) == "EC"
        val dataToSign = if (isEcdsa) {
            MessageDigest.getInstance("SHA-256").digest(signingInput)
        } else {
            signingInput
        }

        val keyLabel = keyManager.listKeys().find { it.alias == req.handle }?.label ?: req.handle
        val deviceName = authenticatedDeviceKey?.let { trustStore?.getDevice(it)?.label }

        callback.requestBiometricSign(req.handle, keyLabel, deviceName, dataToSign) { signature ->
            operationInProgress.set(false)
            if (signature == null) {
                onResponse(SshWireFormat.frameMessage(AgentMessageBuilder.failure()))
                return@requestBiometricSign
            }

            keyManager.updateLastUsed(req.handle)

            val sigBlock = ByteArray(64)
            if (isEcdsa) {
                val (r, s) = try {
                    SshWireFormat.extractRawEcdsaComponents(signature)
                } catch (e: Exception) {
                    Log.e(TAG, "SK sign: failed to parse ECDSA signature: $e")
                    onResponse(SshWireFormat.frameMessage(AgentMessageBuilder.failure()))
                    return@requestBiometricSign
                }
                System.arraycopy(r, 0, sigBlock, 0, 32)
                System.arraycopy(s, 0, sigBlock, 32, 32)
            } else {
                System.arraycopy(signature, 0, sigBlock, 0, minOf(64, signature.size))
            }

            // SK_SIGN_RESPONSE: [type:1][sig:64][counter:4][flags:1]
            val response = ByteArray(70)
            response[0] = AgentMessageType.SK_SIGN_RESPONSE
            System.arraycopy(sigBlock, 0, response, 1, 64)
            response[65] = (counter shr 24).toByte()
            response[66] = (counter shr 16).toByte()
            response[67] = (counter shr 8).toByte()
            response[68] = counter.toByte()
            response[69] = (req.flags.toInt() or 0x01).toByte()
            onResponse(SshWireFormat.frameMessage(response))
        }
    }

    private fun handleSkLoadResident(onResponse: (ByteArray) -> Unit) {
        if (!operationInProgress.compareAndSet(false, true)) {
            Log.w(TAG, "SK load resident: rejected — another operation in progress")
            onResponse(SshWireFormat.frameMessage(AgentMessageBuilder.failure()))
            return
        }

        val allKeys = keyManager.listKeys()
        val residentKeys = allKeys.filter { it.resident }
        Log.i(TAG, "SK load resident: ${residentKeys.size} resident keys of ${allKeys.size} total")

        val deviceName = authenticatedDeviceKey?.let { trustStore?.getDevice(it)?.label }
        callback.requestResidentKeysAccess(residentKeys.size, deviceName) { accepted ->
            if (!accepted) {
                operationInProgress.set(false)
                Log.i(TAG, "SK load resident: user denied access")
                onResponse(SshWireFormat.frameMessage(AgentMessageBuilder.failure()))
                return@requestResidentKeysAccess
            }
            doLoadResident(residentKeys, onResponse)
        }
    }

    private fun doLoadResident(residentKeys: List<com.example.pocketsshagent.model.KeyMetadata>, onResponse: (ByteArray) -> Unit) {

        data class ResidentEntry(val alg: Byte, val app: ByteArray, val pubkey: ByteArray, val handle: ByteArray, val flags: Byte)

        val entries = mutableListOf<ResidentEntry>()
        val defaultApp = "ssh:".toByteArray(Charsets.UTF_8)

        for (meta in residentKeys) {
            try {
                val algorithm = keyManager.getKeyAlgorithm(meta.alias)
                val isEcdsa = algorithm == "EC"
                val alg: Byte = if (isEcdsa) 0 else 1
                val encoded = keyManager.getPublicKey(meta.alias).encoded
                val rawPubKey = if (isEcdsa) SshWireFormat.extractRawP256PublicKey(encoded)
                               else SshWireFormat.extractRawEd25519PublicKey(encoded)
                val handle = meta.alias.toByteArray(Charsets.UTF_8)
                entries.add(ResidentEntry(alg, defaultApp, rawPubKey, handle, 0x01))
            } catch (e: Exception) {
                Log.w(TAG, "SK load resident: skipping ${meta.alias}: $e")
            }
        }

        var size = 1 + 2
        for (e in entries) {
            size += 1 + 2 + e.app.size + 2 + e.pubkey.size + 2 + e.handle.size + 1
        }
        val response = ByteArray(size)
        var off = 0
        response[off++] = AgentMessageType.SK_LOAD_RESIDENT_RESPONSE
        response[off++] = (entries.size shr 8).toByte()
        response[off++] = (entries.size and 0xFF).toByte()
        for (e in entries) {
            response[off++] = e.alg
            response[off++] = (e.app.size shr 8).toByte()
            response[off++] = (e.app.size and 0xFF).toByte()
            System.arraycopy(e.app, 0, response, off, e.app.size); off += e.app.size
            response[off++] = (e.pubkey.size shr 8).toByte()
            response[off++] = (e.pubkey.size and 0xFF).toByte()
            System.arraycopy(e.pubkey, 0, response, off, e.pubkey.size); off += e.pubkey.size
            response[off++] = (e.handle.size shr 8).toByte()
            response[off++] = (e.handle.size and 0xFF).toByte()
            System.arraycopy(e.handle, 0, response, off, e.handle.size); off += e.handle.size
            response[off++] = e.flags
        }
        operationInProgress.set(false)
        onResponse(SshWireFormat.frameMessage(response))
    }
}
