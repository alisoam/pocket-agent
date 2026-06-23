package com.example.pocketsshagent.crypto

import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.spec.X509EncodedKeySpec

/**
 * Per-session encryption using ephemeral X25519 ECDH + AES-256-GCM.
 *
 * Key derivation: HKDF-SHA256(IKM=X25519SharedSecret, salt=authNonce,
 *                             info="pocket-ssh-session" || 0x00 || version)
 * Wire format:    [12B nonce][ciphertext][16B GCM auth tag]
 *
 * The `version` byte is the negotiated session protocol version from the auth
 * handshake. Binding it into the KDF means a downgrade attacker who strips
 * features cannot make two peers agree on the same key for different versions.
 *
 * Must mirror the proxy's deriveSessionKey / sealAESGCM / openAESGCM in ble/client.go.
 */
class SessionCrypto private constructor(private val key: ByteArray) {

    companion object {
        private const val NONCE_BYTES = 12
        private const val TAG_BITS = 128

        // SubjectPublicKeyInfo header for X25519 (RFC 8410, OID 1.3.101.110)
        // 30 2a 30 05 06 03 2b 65 6e 03 21 00
        private val X25519_SPKI_HEADER = byteArrayOf(
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00
        )

        /**
         * Generate an ephemeral X25519 keypair, perform ECDH with the proxy's
         * raw 32-byte public key, derive the session key, and return:
         *   - the ready-to-use [SessionCrypto]
         *   - our raw 32-byte public key to send back in the 101 response
         */
        fun establish(
            proxyEphemeralPubRaw: ByteArray,
            salt: ByteArray,
            negotiatedVersion: Int
        ): Pair<SessionCrypto, ByteArray> {
            val kpg = KeyPairGenerator.getInstance("X25519")
            val keyPair = kpg.generateKeyPair()

            // SubjectPublicKeyInfo is 44 bytes; raw key is the last 32
            val ourPubRaw = keyPair.public.encoded.copyOfRange(12, 44)

            val proxyPub = KeyFactory.getInstance("X25519")
                .generatePublic(X509EncodedKeySpec(X25519_SPKI_HEADER + proxyEphemeralPubRaw))

            val ka = KeyAgreement.getInstance("X25519")
            ka.init(keyPair.private)
            ka.doPhase(proxyPub, true)
            val sharedSecret = ka.generateSecret()

            // HKDF info: "pocket-ssh-session" || 0x00 || version
            // The single-block HKDF-Expand counter (0x01) is appended inside hkdfSha256.
            val infoPrefix = "pocket-ssh-session".toByteArray(Charsets.US_ASCII)
            val info = infoPrefix + byteArrayOf(0x00, (negotiatedVersion and 0xFF).toByte())

            val sessionKey = hkdfSha256(
                ikm  = sharedSecret,
                salt = salt,
                info = info
            )

            return SessionCrypto(sessionKey) to ourPubRaw
        }

        /**
         * Wrap a raw symmetric key (e.g. a per-request key generated for the
         * Termux content-provider channel) in a [SessionCrypto] so the exact
         * same [seal]/[open] wire format is reused. [key] must be 32 bytes for
         * AES-256.
         */
        fun withRawKey(key: ByteArray): SessionCrypto {
            require(key.size == 32) { "AES-256 key must be 32 bytes, got ${key.size}" }
            return SessionCrypto(key)
        }

        /**
         * HKDF-SHA256 single-block extract+expand (RFC 5869).
         * Expand inputs HMAC(PRK, info || 0x01); the trailing counter byte is
         * appended here so callers pass only the semantic `info` bytes.
         */
        private fun hkdfSha256(ikm: ByteArray, salt: ByteArray, info: ByteArray): ByteArray {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(salt, "HmacSHA256"))
            val prk = mac.doFinal(ikm)

            val mac2 = Mac.getInstance("HmacSHA256")
            mac2.init(SecretKeySpec(prk, "HmacSHA256"))
            mac2.update(info)
            mac2.update(byteArrayOf(0x01))
            return mac2.doFinal()
        }
    }

    /** Encrypt plaintext. Output: [12B nonce][ciphertext][16B tag] */
    fun seal(plaintext: ByteArray): ByteArray {
        val nonce = ByteArray(NONCE_BYTES).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, nonce))
        return nonce + cipher.doFinal(plaintext)
    }

    /** Decrypt ciphertext produced by [seal]. Throws on authentication failure. */
    fun open(data: ByteArray): ByteArray {
        require(data.size >= NONCE_BYTES + TAG_BITS / 8) { "Ciphertext too short: ${data.size} bytes" }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(key, "AES"),
            GCMParameterSpec(TAG_BITS, data, 0, NONCE_BYTES)
        )
        return cipher.doFinal(data, NONCE_BYTES, data.size - NONCE_BYTES)
    }
}
