package com.example.pocketsshagent.pairing

import android.util.Base64
import android.util.Log
import org.json.JSONObject
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

/**
 * QR pairing payload format and verification.
 *
 * The desktop proxy generates a QR code containing a JSON payload:
 * {
 *   "version": 1,
 *   "publicKey": "<base64 Ed25519 public key (X.509/PKIX encoded)>",
 *   "nonce": "<base64 random 32 bytes>",
 *   "label": "My Laptop",
 *   "signature": "<base64 Ed25519 signature of nonce using the desktop's key>"
 * }
 *
 * The phone verifies that the signature matches the public key and nonce,
 * then stores the public key in the trust store.
 */
object PairingProtocol {

    private const val TAG = "PairingProtocol"
    private const val VERSION = 1

    data class PairingPayload(
        val publicKey: ByteArray,  // X.509 encoded
        val nonce: ByteArray,
        val label: String,
        val signature: ByteArray
    )

    /**
     * Parse a QR code string into a pairing payload.
     * Returns null if parsing fails.
     */
    fun parseQrPayload(qrContent: String): PairingPayload? {
        return try {
            val json = JSONObject(qrContent)
            val version = json.getInt("version")
            if (version != VERSION) {
                Log.w(TAG, "Unsupported pairing version: $version")
                return null
            }
            PairingPayload(
                publicKey = Base64.decode(json.getString("publicKey"), Base64.NO_WRAP),
                nonce = Base64.decode(json.getString("nonce"), Base64.NO_WRAP),
                label = json.getString("label"),
                signature = Base64.decode(json.getString("signature"), Base64.NO_WRAP)
            )
        } catch (e: Exception) {
            Log.e(TAG, "Failed to parse QR payload", e)
            null
        }
    }

    /**
     * Verify the pairing payload: check that the signature over the nonce
     * is valid for the provided public key.
     */
    fun verifyPayload(payload: PairingPayload): Boolean {
        return try {
            val keySpec = X509EncodedKeySpec(payload.publicKey)
            val keyFactory = KeyFactory.getInstance("Ed25519")
            val publicKey = keyFactory.generatePublic(keySpec)

            val sig = Signature.getInstance("Ed25519")
            sig.initVerify(publicKey)
            sig.update(payload.nonce)
            sig.verify(payload.signature)
        } catch (e: Exception) {
            Log.e(TAG, "Payload verification failed", e)
            false
        }
    }

    /**
     * Complete pairing: verify and add to trust store.
     * Returns the TrustedDevice on success, null on failure.
     */
    fun completePairing(qrContent: String, trustStore: TrustStore): TrustedDevice? {
        val payload = parseQrPayload(qrContent) ?: return null

        if (!verifyPayload(payload)) {
            Log.w(TAG, "Pairing verification failed — rejecting device")
            return null
        }

        val publicKeyBase64 = Base64.encodeToString(payload.publicKey, Base64.NO_WRAP)
        val device = TrustedDevice(
            publicKey = publicKeyBase64,
            label = payload.label,
            pairedAtEpochMs = System.currentTimeMillis()
        )
        trustStore.addDevice(device)
        Log.i(TAG, "Paired with device: ${device.label}")
        return device
    }
}
