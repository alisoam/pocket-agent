package com.example.pocketsshagent.pairing

import android.content.Context
import android.content.SharedPreferences
import org.json.JSONObject

/**
 * Persists trusted paired devices.
 * Each device is identified by its Ed25519 public key (base64-encoded).
 */
class TrustStore(context: Context) {

    private val prefs: SharedPreferences =
        context.getSharedPreferences("trust_store", Context.MODE_PRIVATE)

    fun addDevice(device: TrustedDevice) {
        val json = JSONObject().apply {
            put("publicKey", device.publicKey)
            put("label", device.label)
            put("pairedAtEpochMs", device.pairedAtEpochMs)
            put("lastSeenAtEpochMs", device.lastSeenAtEpochMs)
        }
        prefs.edit().putString(device.publicKey, json.toString()).apply()
    }

    fun removeDevice(publicKey: String) {
        prefs.edit().remove(publicKey).apply()
    }

    fun getDevice(publicKey: String): TrustedDevice? {
        val raw = prefs.getString(publicKey, null) ?: return null
        return parseDevice(raw)
    }

    fun isTrusted(publicKey: String): Boolean {
        return prefs.contains(publicKey)
    }

    fun getAllDevices(): List<TrustedDevice> {
        return prefs.all.values.mapNotNull { value ->
            (value as? String)?.let { parseDevice(it) }
        }.sortedByDescending { it.pairedAtEpochMs }
    }

    fun updateLastSeen(publicKey: String) {
        val device = getDevice(publicKey) ?: return
        addDevice(device.copy(lastSeenAtEpochMs = System.currentTimeMillis()))
    }

    private fun parseDevice(json: String): TrustedDevice? {
        return try {
            val obj = JSONObject(json)
            TrustedDevice(
                publicKey = obj.getString("publicKey"),
                label = obj.getString("label"),
                pairedAtEpochMs = obj.getLong("pairedAtEpochMs"),
                lastSeenAtEpochMs = obj.optLong("lastSeenAtEpochMs", 0L)
            )
        } catch (_: Exception) {
            null
        }
    }
}

data class TrustedDevice(
    val publicKey: String, // Base64-encoded Ed25519 public key
    val label: String,
    val pairedAtEpochMs: Long,
    val lastSeenAtEpochMs: Long = 0L
)
