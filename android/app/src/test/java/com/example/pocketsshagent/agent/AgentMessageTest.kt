package com.example.pocketsshagent.agent

import org.junit.Assert.*
import org.junit.Test

class AgentMessageTest {

    @Test
    fun `failure response`() {
        val response = AgentMessageBuilder.failure()
        assertEquals(1, response.size)
        assertEquals(AgentMessageType.SSH_AGENT_FAILURE, response[0])
    }

    @Test
    fun `authFailure response`() {
        val response = AgentMessageBuilder.authFailure()
        assertEquals(1, response.size)
        assertEquals(AgentMessageType.POCKET_AUTH_FAILURE, response[0])
    }

    @Test
    fun `authSuccess response structure`() {
        val ephemeralPub = ByteArray(32) { it.toByte() }
        val version = 1
        val response = AgentMessageBuilder.authSuccess(ephemeralPub, version)

        assertEquals(AgentMessageType.POCKET_AUTH_SUCCESS, response[0])

        val (pubKey, offset) = SshWireFormat.decodeString(response, 1)
        assertArrayEquals(ephemeralPub, pubKey)

        assertEquals(version, response[offset].toInt() and 0xFF)
    }

    @Test
    fun `messageType extracts first byte`() {
        val msg = byteArrayOf(AgentMessageType.POCKET_AUTH_REQUEST)
        assertEquals(AgentMessageType.POCKET_AUTH_REQUEST, AgentMessageParser.messageType(msg))
    }

    @Test(expected = IllegalArgumentException::class)
    fun `messageType rejects empty message`() {
        AgentMessageParser.messageType(byteArrayOf())
    }

    @Test
    fun `parseAuthRequest round-trip`() {
        val publicKey = ByteArray(44) { it.toByte() }
        val nonce = ByteArray(32) { (it + 50).toByte() }
        val signature = ByteArray(64) { (it + 100).toByte() }
        val x25519Key = ByteArray(32) { (it + 200).toByte() }
        val clientVersion = 1

        val message = byteArrayOf(AgentMessageType.POCKET_AUTH_REQUEST) +
                SshWireFormat.encodeString(publicKey) +
                SshWireFormat.encodeString(nonce) +
                SshWireFormat.encodeString(signature) +
                SshWireFormat.encodeString(x25519Key) +
                byteArrayOf(clientVersion.toByte())

        val parsed = AgentMessageParser.parseAuthRequest(message)
        assertArrayEquals(publicKey, parsed.publicKey)
        assertArrayEquals(nonce, parsed.nonce)
        assertArrayEquals(signature, parsed.signature)
        assertArrayEquals(x25519Key, parsed.x25519EphemeralKey)
        assertEquals(clientVersion, parsed.clientVersion)
    }

    @Test
    fun `parseAuthRequest defaults version to 1 when omitted`() {
        val publicKey = ByteArray(44) { it.toByte() }
        val nonce = ByteArray(32) { (it + 50).toByte() }
        val signature = ByteArray(64) { (it + 100).toByte() }
        val x25519Key = ByteArray(32) { (it + 200).toByte() }

        val message = byteArrayOf(AgentMessageType.POCKET_AUTH_REQUEST) +
                SshWireFormat.encodeString(publicKey) +
                SshWireFormat.encodeString(nonce) +
                SshWireFormat.encodeString(signature) +
                SshWireFormat.encodeString(x25519Key)

        val parsed = AgentMessageParser.parseAuthRequest(message)
        assertEquals(1, parsed.clientVersion)
    }

    @Test
    fun `parseSkEnrollRequest basic`() {
        val appHash = ByteArray(32) { it.toByte() }
        val alg: Byte = 1
        val flags: Byte = 0x01

        val message = ByteArray(35)
        message[0] = AgentMessageType.SK_ENROLL_REQUEST
        message[1] = alg
        System.arraycopy(appHash, 0, message, 2, 32)
        message[34] = flags

        val parsed = AgentMessageParser.parseSkEnrollRequest(message)
        assertEquals(1, parsed.alg)
        assertArrayEquals(appHash, parsed.appHash)
        assertEquals(flags, parsed.flags)
        assertEquals("", parsed.label)
    }

    @Test
    fun `parseSkEnrollRequest with label`() {
        val appHash = ByteArray(32) { it.toByte() }
        val label = "test-key"
        val labelBytes = label.toByteArray(Charsets.UTF_8)

        val message = ByteArray(35 + 2 + labelBytes.size)
        message[0] = AgentMessageType.SK_ENROLL_REQUEST
        message[1] = 0
        System.arraycopy(appHash, 0, message, 2, 32)
        message[34] = 0x01
        message[35] = (labelBytes.size shr 8).toByte()
        message[36] = (labelBytes.size and 0xFF).toByte()
        System.arraycopy(labelBytes, 0, message, 37, labelBytes.size)

        val parsed = AgentMessageParser.parseSkEnrollRequest(message)
        assertEquals(label, parsed.label)
    }

    @Test
    fun `parseSkSignRequest round-trip`() {
        val handle = "sk-key-alias"
        val handleBytes = handle.toByteArray(Charsets.UTF_8)
        val appHash = ByteArray(32) { it.toByte() }
        val flags: Byte = 0x01
        val dataHash = ByteArray(32) { (it + 64).toByte() }

        val message = ByteArray(1 + 2 + handleBytes.size + 32 + 1 + 32)
        var off = 0
        message[off++] = AgentMessageType.SK_SIGN_REQUEST
        message[off++] = (handleBytes.size shr 8).toByte()
        message[off++] = (handleBytes.size and 0xFF).toByte()
        System.arraycopy(handleBytes, 0, message, off, handleBytes.size); off += handleBytes.size
        System.arraycopy(appHash, 0, message, off, 32); off += 32
        message[off++] = flags
        System.arraycopy(dataHash, 0, message, off, 32)

        val parsed = AgentMessageParser.parseSkSignRequest(message)
        assertEquals(handle, parsed.handle)
        assertArrayEquals(appHash, parsed.appHash)
        assertEquals(flags, parsed.flags)
        assertArrayEquals(dataHash, parsed.dataHash)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `parseSkEnrollRequest rejects wrong type`() {
        AgentMessageParser.parseSkEnrollRequest(byteArrayOf(AgentMessageType.SSH_AGENT_FAILURE))
    }

    @Test(expected = IllegalArgumentException::class)
    fun `parseSkSignRequest rejects wrong type`() {
        AgentMessageParser.parseSkSignRequest(byteArrayOf(AgentMessageType.SSH_AGENT_FAILURE))
    }
}
