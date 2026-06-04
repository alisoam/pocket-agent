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
    fun `encodeEd25519PublicKey structure`() {
        val fakeKey = ByteArray(32) { it.toByte() }
        val blob = SshWireFormat.encodeEd25519PublicKey(fakeKey)

        // Should be: string("ssh-ed25519") + string(32-byte key)
        // = (4 + 11) + (4 + 32) = 51 bytes
        assertEquals(51, blob.size)

        val (keyType, offset1) = SshWireFormat.decodeString(blob, 0)
        assertEquals("ssh-ed25519", String(keyType, Charsets.UTF_8))

        val (keyData, offset2) = SshWireFormat.decodeString(blob, offset1)
        assertEquals(32, keyData.size)
        assertArrayEquals(fakeKey, keyData)
        assertEquals(51, offset2)
    }

    @Test
    fun `encodeEd25519Signature structure`() {
        val fakeSig = ByteArray(64) { (it + 100).toByte() }
        val blob = SshWireFormat.encodeEd25519Signature(fakeSig)

        // string("ssh-ed25519") + string(64-byte sig)
        // = (4 + 11) + (4 + 64) = 83 bytes
        assertEquals(83, blob.size)

        val (sigType, offset1) = SshWireFormat.decodeString(blob, 0)
        assertEquals("ssh-ed25519", String(sigType, Charsets.UTF_8))

        val (sigData, _) = SshWireFormat.decodeString(blob, offset1)
        assertArrayEquals(fakeSig, sigData)
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
        // Construct a valid X.509 Ed25519 SubjectPublicKeyInfo (44 bytes)
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
}
