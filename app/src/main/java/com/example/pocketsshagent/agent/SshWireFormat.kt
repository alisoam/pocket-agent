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
     * X.509 Ed25519 format: 12-byte header + 32-byte key.
     */
    fun extractRawEd25519PublicKey(x509Encoded: ByteArray): ByteArray {
        // Ed25519 X.509 SubjectPublicKeyInfo is always 44 bytes:
        // 30 2a 30 05 06 03 2b 65 70 03 21 00 <32 bytes>
        require(x509Encoded.size == 44) {
            "Unexpected X.509 Ed25519 public key size: ${x509Encoded.size}"
        }
        return x509Encoded.copyOfRange(12, 44)
    }
}
