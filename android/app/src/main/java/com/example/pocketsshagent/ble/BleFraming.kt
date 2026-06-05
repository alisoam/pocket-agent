package com.example.pocketsshagent.ble

import android.util.Log
import com.example.pocketsshagent.agent.SshWireFormat
import java.io.ByteArrayOutputStream

/**
 * Handles chunking outgoing messages to fit BLE MTU and reassembling
 * incoming chunks into complete SSH agent messages.
 *
 * SSH agent messages are length-prefixed (4-byte uint32 + payload).
 * BLE has a limited MTU (typically 20-512 bytes), so messages must be
 * split into chunks for transmission and reassembled on receipt.
 *
 * Framing protocol:
 * - Each BLE write/notification carries a raw chunk of the framed message.
 * - The receiver uses the 4-byte length prefix to know when a full message
 *   has been received.
 */
class BleFrameAssembler {

    private val buffer = ByteArrayOutputStream()
    private var expectedLength: Int = -1

    companion object {
        private const val TAG = "BleFrameAssembler"
        // Mirrors maxBleFrameBytes in the Go proxy — prevents OOM from a bogus length field.
        private const val MAX_FRAME_BYTES = 64 * 1024
    }

    /**
     * Feed incoming chunk data. Returns a complete message (without the
     * 4-byte length prefix) when fully assembled, or null if more data needed.
     */
    fun feed(chunk: ByteArray): ByteArray? {
        buffer.write(chunk)

        val accumulated = buffer.toByteArray()

        // Need at least 4 bytes to read the length prefix
        if (accumulated.size < 4) return null

        if (expectedLength < 0) {
            val declared = SshWireFormat.decodeUint32(accumulated, 0)
            if (declared > MAX_FRAME_BYTES) {
                Log.w(TAG, "Oversized frame declared ($declared bytes > $MAX_FRAME_BYTES limit), dropping")
                reset()
                return null
            }
            expectedLength = declared
        }

        val totalNeeded = 4 + expectedLength
        if (accumulated.size < totalNeeded) return null

        // Full message received
        val message = accumulated.copyOfRange(4, totalNeeded)
        reset()
        return message
    }

    /** Reset the assembler for the next message. */
    fun reset() {
        buffer.reset()
        expectedLength = -1
    }
}

/**
 * Splits a framed message (with length prefix) into MTU-sized chunks.
 */
object BleFrameChunker {

    /**
     * Split [framedMessage] into chunks of at most [mtu] bytes.
     * The framedMessage should already include the 4-byte length prefix.
     */
    fun chunk(framedMessage: ByteArray, mtu: Int): List<ByteArray> {
        require(mtu > 0) { "MTU must be positive" }
        val chunks = mutableListOf<ByteArray>()
        var offset = 0
        while (offset < framedMessage.size) {
            val end = minOf(offset + mtu, framedMessage.size)
            chunks.add(framedMessage.copyOfRange(offset, end))
            offset = end
        }
        return chunks
    }
}
