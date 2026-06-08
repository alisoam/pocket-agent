package com.example.pocketsshagent.pairing

import android.util.Base64
import android.util.Log
import org.json.JSONObject
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

/**
 * QR pairing payload format and verification (v2).
 *
 * The desktop proxy generates a QR code containing a JSON payload:
 * {
 *   "version": 2,
 *   "publicKey": "<base64 Ed25519 public key (X.509/PKIX encoded)>",
 *   "nonce": "<base64 random 32 bytes>",
 *   "label": "My Laptop",
 *   "issuedAtMs": 1700000000000,
 *   "expiresAtMs": 1700000300000,
 *   "signature": "<base64 Ed25519 signature over the transcript>"
 * }
 *
 * Signature transcript (must match proxy/internal/pairing.SignatureTranscript):
 *   "pocket-pair-v2\x00"
 *     || uint64BE(issuedAtMs) || uint64BE(expiresAtMs)
 *     || nonce || x509PubKey || utf8(label)
 *
 * Replay resistance: TTL enforced against the phone's clock, and nonces are
 * recorded in [SeenNonceCache] so a leaked QR cannot be re-used within its
 * validity window either.
 */
object PairingProtocol {

    private const val TAG = "PairingProtocol"
    private const val VERSION = 2
    // Domain-separation prefix — MUST match proxy/internal/pairing.signatureDomain
    // (the 14 ASCII bytes "pocket-pair-v2" followed by a single 0x00 byte).
    private val SIGNATURE_DOMAIN: ByteArray =
        "pocket-pair-v2".toByteArray(Charsets.UTF_8) + byteArrayOf(0x00)

    // Tolerate small clock skew between the desktop and the phone.
    private const val CLOCK_SKEW_MS = 60_000L

    data class PairingPayload(
        val publicKey: ByteArray,  // X.509 encoded
        val nonce: ByteArray,
        val label: String,
        val issuedAtMs: Long,
        val expiresAtMs: Long,
        val signature: ByteArray
    )

    sealed class Result {
        data class Success(val device: TrustedDevice) : Result()
        data class Failure(val reason: String) : Result()
    }

    /**
     * Parse a QR code string into a pairing payload.
     * Returns null if parsing fails.
     */
    fun parseQrPayload(qrContent: String): PairingPayload? {
        return try {
            val json = JSONObject(qrContent)
            val version = json.getInt("version")
            if (version != VERSION) {
                Log.w(TAG, "Unsupported pairing version: $version (expected $VERSION)")
                return null
            }
            PairingPayload(
                publicKey = Base64.decode(json.getString("publicKey"), Base64.NO_WRAP),
                nonce = Base64.decode(json.getString("nonce"), Base64.NO_WRAP),
                label = json.getString("label"),
                issuedAtMs = json.getLong("issuedAtMs"),
                expiresAtMs = json.getLong("expiresAtMs"),
                signature = Base64.decode(json.getString("signature"), Base64.NO_WRAP)
            )
        } catch (e: Exception) {
            Log.e(TAG, "Failed to parse QR payload", e)
            null
        }
    }

    private fun buildTranscript(payload: PairingPayload): ByteArray {
        val domainBytes = SIGNATURE_DOMAIN
        val labelBytes = payload.label.toByteArray(Charsets.UTF_8)
        val times = ByteBuffer.allocate(16).order(ByteOrder.BIG_ENDIAN)
            .putLong(payload.issuedAtMs)
            .putLong(payload.expiresAtMs)
            .array()
        val total = domainBytes.size + times.size + payload.nonce.size +
                payload.publicKey.size + labelBytes.size
        val out = ByteArray(total)
        var off = 0
        System.arraycopy(domainBytes, 0, out, off, domainBytes.size); off += domainBytes.size
        System.arraycopy(times, 0, out, off, times.size); off += times.size
        System.arraycopy(payload.nonce, 0, out, off, payload.nonce.size); off += payload.nonce.size
        System.arraycopy(payload.publicKey, 0, out, off, payload.publicKey.size); off += payload.publicKey.size
        System.arraycopy(labelBytes, 0, out, off, labelBytes.size)
        return out
    }

    /**
     * Verify the pairing signature over the v2 transcript.
     */
    fun verifyPayload(payload: PairingPayload): Boolean {
        return try {
            val keySpec = X509EncodedKeySpec(payload.publicKey)
            val keyFactory = KeyFactory.getInstance("Ed25519")
            val publicKey = keyFactory.generatePublic(keySpec)

            val sig = Signature.getInstance("Ed25519")
            sig.initVerify(publicKey)
            sig.update(buildTranscript(payload))
            sig.verify(payload.signature)
        } catch (e: Exception) {
            Log.e(TAG, "Payload verification failed", e)
            false
        }
    }

    /**
     * Complete pairing: parse, verify signature, enforce TTL, reject replays,
     * and add to the trust store.
     */
    fun completePairing(
        qrContent: String,
        trustStore: TrustStore,
        seenNonces: SeenNonceCache,
        nowMs: Long = System.currentTimeMillis()
    ): Result {
        val payload = parseQrPayload(qrContent)
            ?: return Result.Failure("Invalid or unsupported QR payload")

        Log.i(TAG, "Pairing attempt: now=$nowMs issued=${payload.issuedAtMs} " +
                "expires=${payload.expiresAtMs} ageMs=${nowMs - payload.issuedAtMs} " +
                "remainingMs=${payload.expiresAtMs - nowMs}")

        if (payload.nonce.size != 32) {
            Log.w(TAG, "Reject: invalid nonce length ${payload.nonce.size}")
            return Result.Failure("Invalid nonce length")
        }
        if (payload.expiresAtMs <= payload.issuedAtMs) {
            Log.w(TAG, "Reject: invalid validity window")
            return Result.Failure("Invalid validity window")
        }
        if (nowMs + CLOCK_SKEW_MS < payload.issuedAtMs) {
            Log.w(TAG, "Reject: QR not valid yet (phone clock behind by " +
                    "${payload.issuedAtMs - nowMs} ms)")
            return Result.Failure("QR code is not valid yet — check clocks")
        }
        if (nowMs - CLOCK_SKEW_MS > payload.expiresAtMs) {
            Log.w(TAG, "Reject: QR expired ${nowMs - payload.expiresAtMs} ms ago")
            return Result.Failure("QR code has expired — generate a new one")
        }

        if (!verifyPayload(payload)) {
            Log.w(TAG, "Reject: signature verification failed")
            return Result.Failure("Signature verification failed")
        }

        // Replay guard: refuse to honor the same nonce twice, even within the
        // TTL. Record AFTER signature verification so unverified payloads
        // can't pollute the cache.
        if (!seenNonces.recordIfNew(payload.nonce, payload.expiresAtMs)) {
            return Result.Failure("QR code has already been used")
        }

        val publicKeyBase64 = Base64.encodeToString(payload.publicKey, Base64.NO_WRAP)
        val device = TrustedDevice(
            publicKey = publicKeyBase64,
            label = payload.label,
            pairedAtEpochMs = nowMs
        )
        trustStore.addDevice(device)
        Log.i(TAG, "Paired with device: ${device.label}")
        return Result.Success(device)
    }
}
