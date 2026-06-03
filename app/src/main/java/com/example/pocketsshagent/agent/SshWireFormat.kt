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
     * Frame an agent message: uint32 length prefix + message bytes.
     */
    fun frameMessage(message: ByteArray): ByteArray {
        return encodeUint32(message.size) + message
    }

    // ── Ed25519 ──────────────────────────────────────────────────────────────

    /**
     * Returns true if the X.509-encoded public key is an Ed25519 key.
     * More reliable than PublicKey.algorithm, which some OEMs report as "EC".
     */
    fun isEd25519PublicKey(encoded: ByteArray): Boolean {
        val oid = byteArrayOf(0x06, 0x03, 0x2b, 0x65, 0x70) // OID 1.3.101.112
        return findSubArray(encoded, oid) >= 0
    }

    /**
     * Extract the raw 32-byte Ed25519 public key from X.509 encoding.
     */
    fun extractRawEd25519PublicKey(x509Encoded: ByteArray): ByteArray {
        if (x509Encoded.size == 44) return x509Encoded.copyOfRange(12, 44)
        val oid = byteArrayOf(0x06, 0x03, 0x2b, 0x65, 0x70)
        if (findSubArray(x509Encoded, oid) >= 0) {
            val keyStart = x509Encoded.size - 32
            if (keyStart > 0) return x509Encoded.copyOfRange(keyStart, x509Encoded.size)
        }
        require(x509Encoded.size >= 32) { "Encoded key too short: ${x509Encoded.size}" }
        return x509Encoded.copyOfRange(x509Encoded.size - 32, x509Encoded.size)
    }

    /**
     * Encode an Ed25519 public key in SSH wire format:
     *   string "ssh-ed25519"  |  string <32-byte key>
     */
    fun encodeEd25519PublicKey(rawKey: ByteArray): ByteArray =
        encodeString("ssh-ed25519") + encodeString(rawKey)

    /**
     * Encode an Ed25519 signature in SSH wire format:
     *   string "ssh-ed25519"  |  string <64-byte signature>
     */
    fun encodeEd25519Signature(sig: ByteArray): ByteArray =
        encodeString("ssh-ed25519") + encodeString(sig)

    // ── ECDSA P-256 ──────────────────────────────────────────────────────────

    /**
     * Returns true if the X.509-encoded public key is a P-256 (secp256r1) key.
     */
    fun isP256PublicKey(encoded: ByteArray): Boolean {
        // OID 1.2.840.10045.3.1.7
        val oid = byteArrayOf(0x06, 0x08, 0x2a, 0x86.toByte(), 0x48, 0xce.toByte(), 0x3d, 0x03, 0x01, 0x07)
        return findSubArray(encoded, oid) >= 0
    }

    /**
     * Extract the 65-byte uncompressed EC point (04 || x || y) from a P-256 X.509 key.
     * Standard P-256 SubjectPublicKeyInfo is 91 bytes; the point is always the last 65.
     */
    fun extractRawP256PublicKey(encoded: ByteArray): ByteArray {
        require(encoded.size >= 65) { "P-256 encoding too short: ${encoded.size}" }
        return encoded.copyOfRange(encoded.size - 65, encoded.size)
    }

    /**
     * Encode a P-256 public key in SSH wire format (RFC 5656):
     *   string "ecdsa-sha2-nistp256"  |  string "nistp256"  |  string <65-byte EC point>
     */
    fun encodeEcdsaP256PublicKey(ecPoint: ByteArray): ByteArray =
        encodeString("ecdsa-sha2-nistp256") + encodeString("nistp256") + encodeString(ecPoint)

    /**
     * Encode an ECDSA P-256 signature in SSH wire format (RFC 5656):
     *   string "ecdsa-sha2-nistp256"  |  string (mpint r || mpint s)
     * Input: raw DER-encoded signature SEQUENCE { INTEGER r, INTEGER s } from Android.
     */
    fun encodeEcdsaP256SignatureFromDer(der: ByteArray): ByteArray {
        val (r, s) = parseDerIntegers(der)
        val inner = encodeSshMpint(r) + encodeSshMpint(s)
        return encodeString("ecdsa-sha2-nistp256") + encodeString(inner)
    }

    private fun parseDerIntegers(der: ByteArray): Pair<ByteArray, ByteArray> {
        var pos = 0
        check(der[pos++] == 0x30.toByte()) { "Expected SEQUENCE tag" }
        val seqLen = der[pos++].toInt() and 0xFF
        if (seqLen and 0x80 != 0) pos += seqLen and 0x7F // long-form length
        check(der[pos++] == 0x02.toByte()) { "Expected INTEGER tag (r)" }
        val rLen = der[pos++].toInt() and 0xFF
        val r = der.copyOfRange(pos, pos + rLen); pos += rLen
        check(der[pos++] == 0x02.toByte()) { "Expected INTEGER tag (s)" }
        val sLen = der[pos++].toInt() and 0xFF
        val s = der.copyOfRange(pos, pos + sLen)
        return r to s
    }

    private fun encodeSshMpint(value: ByteArray): ByteArray {
        var v = value.dropWhile { it == 0.toByte() }.toByteArray()
        if (v.isEmpty()) v = byteArrayOf(0)
        if (v[0].toInt() and 0x80 != 0) v = byteArrayOf(0) + v // positive sign byte
        return encodeString(v)
    }

    // ─────────────────────────────────────────────────────────────────────────

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
