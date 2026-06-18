package com.example.pocketsshagent.data

import android.content.Context

class SettingsStore(context: Context) {
    private val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    var bleEnabled: Boolean
        get() = prefs.getBoolean(KEY_BLE_ENABLED, true)
        set(value) = prefs.edit().putBoolean(KEY_BLE_ENABLED, value).apply()

    var termuxEnabled: Boolean
        get() = prefs.getBoolean(KEY_TERMUX_ENABLED, true)
        set(value) = prefs.edit().putBoolean(KEY_TERMUX_ENABLED, value).apply()

    companion object {
        private const val PREFS_NAME = "app_settings"
        private const val KEY_BLE_ENABLED = "ble_enabled"
        private const val KEY_TERMUX_ENABLED = "termux_enabled"
    }
}
