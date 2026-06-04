package com.example.pocketsshagent.ble

import java.util.UUID

/**
 * UUIDs for the SSH Agent BLE GATT service and characteristics.
 */
object BleUuids {
    /** SSH Agent GATT Service UUID. */
    val SSH_AGENT_SERVICE: UUID = UUID.fromString("a11e1f4e-c8a0-4d3b-9f6a-1a2b3c4d5e6f")

    /** RX Characteristic — client writes agent requests here. */
    val AGENT_RX: UUID = UUID.fromString("a12e1f4e-c8a0-4d3b-9f6a-1a2b3c4d5e70")

    /** TX Characteristic — agent sends responses via notifications here. */
    val AGENT_TX: UUID = UUID.fromString("a12e1f4e-c8a0-4d3b-9f6a-1a2b3c4d5e71")

    /** Client Characteristic Configuration Descriptor (standard). */
    val CCCD: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")
}
