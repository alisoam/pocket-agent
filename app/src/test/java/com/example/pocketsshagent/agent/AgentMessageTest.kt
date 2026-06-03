package com.example.pocketsshagent.agent

import org.junit.Assert.*
import org.junit.Test

class AgentMessageTest {

    @Test
    fun `identitiesAnswer with no keys`() {
        val response = AgentMessageBuilder.identitiesAnswer(emptyList())
        assertEquals(AgentMessageType.SSH_AGENT_IDENTITIES_ANSWER, response[0])
        // nkeys = 0
        assertEquals(0, SshWireFormat.decodeUint32(response, 1))
        assertEquals(5, response.size) // 1 type + 4 nkeys
    }

    @Test
    fun `identitiesAnswer with one key`() {
        val fakeBlob = ByteArray(51) { it.toByte() }
        val comment = "test-key"
        val response = AgentMessageBuilder.identitiesAnswer(listOf(fakeBlob to comment))

        assertEquals(AgentMessageType.SSH_AGENT_IDENTITIES_ANSWER, response[0])
        assertEquals(1, SshWireFormat.decodeUint32(response, 1))

        // After type(1) + nkeys(4), read key blob string
        val (blob, offset1) = SshWireFormat.decodeString(response, 5)
        assertArrayEquals(fakeBlob, blob)

        // Read comment string
        val (commentBytes, _) = SshWireFormat.decodeString(response, offset1)
        assertEquals(comment, String(commentBytes, Charsets.UTF_8))
    }

    @Test
    fun `signResponse structure`() {
        val fakeSig = ByteArray(64) { it.toByte() }
        val response = AgentMessageBuilder.signResponse(fakeSig)

        assertEquals(AgentMessageType.SSH_AGENT_SIGN_RESPONSE, response[0])

        // After type byte, there's a string wrapping the encoded signature
        val (outerSig, _) = SshWireFormat.decodeString(response, 1)

        // outerSig should be encodeEd25519Signature(fakeSig) = 83 bytes
        assertEquals(83, outerSig.size)

        // Parse the inner structure
        val (sigType, off1) = SshWireFormat.decodeString(outerSig, 0)
        assertEquals("ssh-ed25519", String(sigType, Charsets.UTF_8))

        val (sigData, _) = SshWireFormat.decodeString(outerSig, off1)
        assertArrayEquals(fakeSig, sigData)
    }

    @Test
    fun `failure response`() {
        val response = AgentMessageBuilder.failure()
        assertEquals(1, response.size)
        assertEquals(AgentMessageType.SSH_AGENT_FAILURE, response[0])
    }

    @Test
    fun `parseSignRequest round-trip`() {
        // Build a sign request manually
        val keyBlob = ByteArray(51) { (it + 10).toByte() }
        val data = "test data to sign".toByteArray()
        val flags = 0

        val message = byteArrayOf(AgentMessageType.SSH_AGENTC_SIGN_REQUEST) +
                SshWireFormat.encodeString(keyBlob) +
                SshWireFormat.encodeString(data) +
                SshWireFormat.encodeUint32(flags)

        val parsed = AgentMessageParser.parseSignRequest(message)
        assertArrayEquals(keyBlob, parsed.keyBlob)
        assertArrayEquals(data, parsed.data)
        assertEquals(0, parsed.flags)
    }

    @Test
    fun `messageType extracts first byte`() {
        val msg = byteArrayOf(AgentMessageType.SSH_AGENTC_REQUEST_IDENTITIES)
        assertEquals(AgentMessageType.SSH_AGENTC_REQUEST_IDENTITIES, AgentMessageParser.messageType(msg))
    }

    @Test(expected = IllegalArgumentException::class)
    fun `parseSignRequest rejects wrong type`() {
        AgentMessageParser.parseSignRequest(byteArrayOf(AgentMessageType.SSH_AGENTC_REQUEST_IDENTITIES))
    }
}
