package com.example.pocketsshagent.pairing

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64

/**
 * Records pairing nonces that have already been honored, so a leaked QR code
 * cannot be used twice even within its validity window.
 *
 * Entries are kept until their associated `expiresAtMs` has passed, at which
 * point the TTL check in [PairingProtocol] would reject the QR anyway and the
 * entry is garbage-collected on the next access.
 */
class SeenNonceCache(context: Context) {

    private val prefs: SharedPreferences =
        context.getSharedPreferences("pairing_seen_nonces", Context.MODE_PRIVATE)

    /**
     * Atomically check-and-insert. Returns true if the nonce was not previously
     * seen (and is now recorded); false if it was already present.
     */
    @Synchronized
    fun recordIfNew(nonce: ByteArray, expiresAtMs: Long): Boolean {
        pruneExpired(System.currentTimeMillis())
        val key = Base64.encodeToString(nonce, Base64.NO_WRAP)
        if (prefs.contains(key)) return false
        prefs.edit().putLong(key, expiresAtMs).apply()
        return true
    }

    private fun pruneExpired(nowMs: Long) {
        val editor = prefs.edit()
        var changed = false
        for ((k, v) in prefs.all) {
            val exp = (v as? Long) ?: continue
            if (exp < nowMs) {
                editor.remove(k)
                changed = true
            }
        }
        if (changed) editor.apply()
    }
}
