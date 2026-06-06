package com.example.pocketsshagent.agent

import java.nio.ByteBuffer
import java.nio.ByteOrder

object SshWireFormat {

    fun encodeUint32(value: Int): ByteArray =
        ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(value).array()

    fun decodeUint32(data: ByteArray, offset: Int): Int =
        ByteBuffer.wrap(data, offset, 4).order(ByteOrder.BIG_ENDIAN).int

    fun encodeString(data: ByteArray): ByteArray {
        val buf = ByteBuffer.allocate(4 + data.size).order(ByteOrder.BIG_ENDIAN)
        buf.putInt(data.size)
        buf.put(data)
        return buf.array()
    }

    fun encodeString(text: String): ByteArray = encodeString(text.toByteArray(Charsets.UTF_8))

    fun decodeString(data: ByteArray, offset: Int): Pair<ByteArray, Int> {
        val length = decodeUint32(data, offset)
        val start = offset + 4
        return data.copyOfRange(start, start + length) to (start + length)
    }

    fun frameMessage(message: ByteArray): ByteArray = encodeUint32(message.size) + message

    // ── Ed25519 ──────────────────────────────────────────────────────────────

    /** Extract the raw 32-byte Ed25519 public key from X.509 encoding. */
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

    // ── ECDSA P-256 ──────────────────────────────────────────────────────────

    /** Extract the 65-byte uncompressed EC point (04 || x || y) from a P-256 X.509 key. */
    fun extractRawP256PublicKey(encoded: ByteArray): ByteArray {
        require(encoded.size >= 65) { "P-256 encoding too short: ${encoded.size}" }
        return encoded.copyOfRange(encoded.size - 65, encoded.size)
    }

    /**
     * Extract raw 32-byte R and S from a DER ECDSA signature.
     * Used for ECDSA-SK sign responses.
     */
    fun extractRawEcdsaComponents(der: ByteArray): Pair<ByteArray, ByteArray> {
        val (r, s) = parseDerIntegers(der)
        fun pad32(v: ByteArray): ByteArray {
            val trimmed = v.dropWhile { it == 0.toByte() }.toByteArray()
            return ByteArray(32 - minOf(trimmed.size, 32)) + trimmed.takeLast(32).toByteArray()
        }
        return pad32(r) to pad32(s)
    }

    private fun parseDerIntegers(der: ByteArray): Pair<ByteArray, ByteArray> {
        var pos = 0
        check(der[pos++] == 0x30.toByte()) { "Expected SEQUENCE tag" }
        val seqLen = der[pos++].toInt() and 0xFF
        if (seqLen and 0x80 != 0) pos += seqLen and 0x7F
        check(der[pos++] == 0x02.toByte()) { "Expected INTEGER tag (r)" }
        val rLen = der[pos++].toInt() and 0xFF
        val r = der.copyOfRange(pos, pos + rLen); pos += rLen
        check(der[pos++] == 0x02.toByte()) { "Expected INTEGER tag (s)" }
        val sLen = der[pos++].toInt() and 0xFF
        val s = der.copyOfRange(pos, pos + sLen)
        return r to s
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
