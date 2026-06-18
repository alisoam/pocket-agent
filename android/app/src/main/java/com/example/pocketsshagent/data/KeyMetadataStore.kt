package com.example.pocketsshagent.data

import android.content.Context
import com.example.pocketsshagent.model.KeyMetadata
import org.json.JSONObject

class KeyMetadataStore(context: Context) {
    private val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    fun getAll(): Map<String, KeyMetadata> {
        val raw = prefs.getString(KEY_METADATA_JSON, null) ?: return emptyMap()
        val root = JSONObject(raw)
        val result = mutableMapOf<String, KeyMetadata>()
        for (alias in root.keys()) {
            val item = root.getJSONObject(alias)
            val metadata = KeyMetadata(
                alias = alias,
                label = item.getString("label"),
                createdAtEpochMs = item.getLong("createdAtEpochMs"),
                lastUsedAtEpochMs = if (item.has("lastUsedAtEpochMs")) item.getLong("lastUsedAtEpochMs") else null,
                hardwareBacked = item.getBoolean("hardwareBacked"),
                skCounter = if (item.has("skCounter")) item.getLong("skCounter") else 0,
                resident = if (item.has("resident")) item.getBoolean("resident") else false
            )
            result[alias] = metadata
        }
        return result
    }

    fun put(metadata: KeyMetadata) {
        val root = getRoot()
        val item = JSONObject()
        item.put("label", metadata.label)
        item.put("createdAtEpochMs", metadata.createdAtEpochMs)
        if (metadata.lastUsedAtEpochMs != null) {
            item.put("lastUsedAtEpochMs", metadata.lastUsedAtEpochMs)
        }
        item.put("hardwareBacked", metadata.hardwareBacked)
        item.put("skCounter", metadata.skCounter)
        item.put("resident", metadata.resident)
        root.put(metadata.alias, item)
        saveRoot(root)
    }

    fun remove(alias: String) {
        val root = getRoot()
        root.remove(alias)
        saveRoot(root)
    }

    private fun getRoot(): JSONObject {
        val raw = prefs.getString(KEY_METADATA_JSON, null) ?: return JSONObject()
        return JSONObject(raw)
    }

    private fun saveRoot(root: JSONObject) {
        prefs.edit().putString(KEY_METADATA_JSON, root.toString()).apply()
    }

    companion object {
        private const val PREFS_NAME = "key_metadata_store"
        private const val KEY_METADATA_JSON = "key_metadata_json"
    }
}
