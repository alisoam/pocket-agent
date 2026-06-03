package com.example.pocketsshagent.ble

import com.example.pocketsshagent.agent.SshWireFormat
import org.junit.Assert.*
import org.junit.Test

class BleFramingTest {

    @Test
    fun `assembler returns null until full message received`() {
        val assembler = BleFrameAssembler()
        val payload = byteArrayOf(11) // REQUEST_IDENTITIES
        val framed = SshWireFormat.frameMessage(payload) // 5 bytes total

        // Feed one byte at a time
        for (i in 0 until framed.size - 1) {
            assertNull(assembler.feed(byteArrayOf(framed[i])))
        }
        val result = assembler.feed(byteArrayOf(framed.last()))
        assertNotNull(result)
        assertArrayEquals(payload, result)
    }

    @Test
    fun `assembler handles single chunk`() {
        val assembler = BleFrameAssembler()
        val payload = ByteArray(100) { it.toByte() }
        val framed = SshWireFormat.frameMessage(payload)

        val result = assembler.feed(framed)
        assertNotNull(result)
        assertArrayEquals(payload, result)
    }

    @Test
    fun `assembler resets for next message`() {
        val assembler = BleFrameAssembler()
        val payload1 = byteArrayOf(11)
        val framed1 = SshWireFormat.frameMessage(payload1)
        val result1 = assembler.feed(framed1)
        assertArrayEquals(payload1, result1)

        // Second message
        val payload2 = byteArrayOf(13, 0, 0, 0, 5)
        val framed2 = SshWireFormat.frameMessage(payload2)
        val result2 = assembler.feed(framed2)
        assertArrayEquals(payload2, result2)
    }

    @Test
    fun `chunker splits message by MTU`() {
        val framed = ByteArray(50) { it.toByte() }
        val chunks = BleFrameChunker.chunk(framed, 20)
        assertEquals(3, chunks.size)
        assertEquals(20, chunks[0].size)
        assertEquals(20, chunks[1].size)
        assertEquals(10, chunks[2].size)

        // Reconstruct
        val reassembled = chunks.reduce { acc, bytes -> acc + bytes }
        assertArrayEquals(framed, reassembled)
    }

    @Test
    fun `chunker with exact MTU`() {
        val framed = ByteArray(40) { it.toByte() }
        val chunks = BleFrameChunker.chunk(framed, 20)
        assertEquals(2, chunks.size)
    }

    @Test
    fun `chunker with large MTU returns single chunk`() {
        val framed = ByteArray(10) { it.toByte() }
        val chunks = BleFrameChunker.chunk(framed, 512)
        assertEquals(1, chunks.size)
        assertArrayEquals(framed, chunks[0])
    }

    @Test
    fun `round-trip chunk and reassemble`() {
        val payload = ByteArray(200) { (it * 3).toByte() }
        val framed = SshWireFormat.frameMessage(payload)
        val chunks = BleFrameChunker.chunk(framed, 23)

        val assembler = BleFrameAssembler()
        var result: ByteArray? = null
        for (chunk in chunks) {
            result = assembler.feed(chunk)
            if (result != null) break
        }
        assertNotNull(result)
        assertArrayEquals(payload, result)
    }
}
