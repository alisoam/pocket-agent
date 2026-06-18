package com.example.pocketsshagent.agent

import org.junit.Assert.*
import org.junit.Test

class SshWireFormatTest {

    @Test
    fun `encodeUint32 and decodeUint32 round-trip`() {
        val values = listOf(0, 1, 255, 256, 65535, 0x7FFFFFFF)
        for (v in values) {
            val encoded = SshWireFormat.encodeUint32(v)
            assertEquals(4, encoded.size)
            assertEquals(v, SshWireFormat.decodeUint32(encoded, 0))
        }
    }

    @Test
    fun `encodeUint32 is big-endian`() {
        val encoded = SshWireFormat.encodeUint32(0x01020304)
        assertArrayEquals(byteArrayOf(1, 2, 3, 4), encoded)
    }

    @Test
    fun `encodeString and decodeString round-trip`() {
        val data = byteArrayOf(0x41, 0x42, 0x43) // "ABC"
        val encoded = SshWireFormat.encodeString(data)
        assertEquals(7, encoded.size) // 4 length + 3 data
        val (decoded, nextOffset) = SshWireFormat.decodeString(encoded, 0)
        assertArrayEquals(data, decoded)
        assertEquals(7, nextOffset)
    }

    @Test
    fun `encodeString text version`() {
        val encoded = SshWireFormat.encodeString("ssh-ed25519")
        val (decoded, _) = SshWireFormat.decodeString(encoded, 0)
        assertEquals("ssh-ed25519", String(decoded, Charsets.UTF_8))
    }

    @Test
    fun `decodeString at offset`() {
        val prefix = byteArrayOf(0xFF.toByte(), 0xFF.toByte())
        val strEncoded = SshWireFormat.encodeString("hello")
        val combined = prefix + strEncoded
        val (decoded, nextOffset) = SshWireFormat.decodeString(combined, 2)
        assertEquals("hello", String(decoded, Charsets.UTF_8))
        assertEquals(2 + 4 + 5, nextOffset)
    }

    @Test
    fun `frameMessage adds length prefix`() {
        val msg = byteArrayOf(11) // REQUEST_IDENTITIES
        val framed = SshWireFormat.frameMessage(msg)
        assertEquals(5, framed.size)
        assertEquals(1, SshWireFormat.decodeUint32(framed, 0))
        assertEquals(11.toByte(), framed[4])
    }

    @Test
    fun `extractRawEd25519PublicKey from X509`() {
        val header = byteArrayOf(
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
            0x70, 0x03, 0x21, 0x00
        )
        val rawKey = ByteArray(32) { (it * 3).toByte() }
        val x509 = header + rawKey

        val extracted = SshWireFormat.extractRawEd25519PublicKey(x509)
        assertArrayEquals(rawKey, extracted)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `extractRawEd25519PublicKey rejects wrong size`() {
        SshWireFormat.extractRawEd25519PublicKey(ByteArray(30))
    }

    @Test
    fun `extractRawP256PublicKey from encoded`() {
        val point = ByteArray(65) { it.toByte() }
        point[0] = 0x04
        val header = byteArrayOf(0x30, 0x59, 0x30, 0x13)
        val encoded = header + point

        val extracted = SshWireFormat.extractRawP256PublicKey(encoded)
        assertArrayEquals(point, extracted)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `extractRawP256PublicKey rejects short input`() {
        SshWireFormat.extractRawP256PublicKey(ByteArray(30))
    }

    @Test
    fun `extractRawEcdsaComponents from DER`() {
        val r = ByteArray(32) { (it + 1).toByte() }
        val s = ByteArray(32) { (it + 33).toByte() }

        val der = byteArrayOf(
            0x30, 68,
            0x02, 32
        ) + r + byteArrayOf(0x02, 32) + s

        val (extractedR, extractedS) = SshWireFormat.extractRawEcdsaComponents(der)
        assertArrayEquals(r, extractedR)
        assertArrayEquals(s, extractedS)
    }
}
