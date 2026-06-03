package com.example.pocketsshagent.agent

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * SSH wire format encoding/decoding utilities.
 * All multi-byte integers are big-endian (network byte order) per RFC 4251.
 */
object SshWireFormat {

    /** Encode a 32-bit unsigned integer. */
    fun encodeUint32(value: Int): ByteArray =
        ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(value).array()

    /** Decode a 32-bit unsigned integer from buffer at given offset. */
    fun decodeUint32(data: ByteArray, offset: Int): Int =
        ByteBuffer.wrap(data, offset, 4).order(ByteOrder.BIG_ENDIAN).int

    /** Encode a byte array as an SSH string (uint32 length + data). */
    fun encodeString(data: ByteArray): ByteArray {
        val buf = ByteBuffer.allocate(4 + data.size).order(ByteOrder.BIG_ENDIAN)
        buf.putInt(data.size)
        buf.put(data)
        return buf.array()
    }

    /** Encode a text string as an SSH string. */
    fun encodeString(text: String): ByteArray = encodeString(text.toByteArray(Charsets.UTF_8))

    /** Decode an SSH string from buffer at given offset. Returns (bytes, nextOffset). */
    fun decodeString(data: ByteArray, offset: Int): Pair<ByteArray, Int> {
        val length = decodeUint32(data, offset)
        val start = offset + 4
        val bytes = data.copyOfRange(start, start + length)
        return bytes to (start + length)
    }

    /**
     * Encode an Ed25519 public key in SSH wire format:
     *   string "ssh-ed25519"
     *   string <32-byte key>
     */
    fun encodeEd25519PublicKey(rawPublicKey: ByteArray): ByteArray {
        val keyType = encodeString("ssh-ed25519")
        val keyData = encodeString(rawPublicKey)
        return keyType + keyData
    }

    /**
     * Encode an Ed25519 signature in SSH wire format:
     *   string "ssh-ed25519"
     *   string <64-byte signature>
     */
    fun encodeEd25519Signature(signatureBytes: ByteArray): ByteArray {
        val sigType = encodeString("ssh-ed25519")
        val sigData = encodeString(signatureBytes)
        return sigType + sigData
    }

    /**
     * Frame an agent message: uint32 length prefix + message bytes.
     */
    fun frameMessage(message: ByteArray): ByteArray {
        return encodeUint32(message.size) + message
    }

    /**
     * Extract the raw 32-byte Ed25519 public key from an X.509/PKIX encoded key.
     * Standard X.509 Ed25519 SubjectPublicKeyInfo is 44 bytes:
     *   30 2a 30 05 06 03 2b 65 70 03 21 00 <32 bytes>
     * But some implementations may vary, so we search for the OID and extract accordingly.
     */
    fun extractRawEd25519PublicKey(x509Encoded: ByteArray): ByteArray {
        // Standard 44-byte format
        if (x509Encoded.size == 44) {
            return x509Encoded.copyOfRange(12, 44)
        }

        // Search for Ed25519 OID: 06 03 2b 65 70
        val oid = byteArrayOf(0x06, 0x03, 0x2b, 0x65, 0x70)
        val oidIndex = findSubArray(x509Encoded, oid)
        if (oidIndex >= 0) {
            // The raw key is the last 32 bytes of the encoding
            val keyStart = x509Encoded.size - 32
            if (keyStart > 0) {
                return x509Encoded.copyOfRange(keyStart, x509Encoded.size)
            }
        }

        // Fallback: assume last 32 bytes are the key
        require(x509Encoded.size >= 32) {
            "Encoded key too short: ${x509Encoded.size} bytes"
        }
        return x509Encoded.copyOfRange(x509Encoded.size - 32, x509Encoded.size)
    }

    private fun findSubArray(haystack: ByteArray, needle: ByteArray): Int {
        outer@ for (i in 0..haystack.size - needle.size) {
            for (j in needle.indices) {
                if (haystack[i + j] != needle[j]) continue@outer
            }
            return i
        }
        return -1
    }
}
