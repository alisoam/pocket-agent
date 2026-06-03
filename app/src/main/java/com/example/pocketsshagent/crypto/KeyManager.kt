package com.example.pocketsshagent.crypto

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import com.example.pocketsshagent.data.KeyMetadataStore
import com.example.pocketsshagent.model.KeyMetadata
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.time.Instant

class KeyManager(private val context: Context) {
    private val store = KeyMetadataStore(context)

    fun generateKey(label: String): KeyMetadata {
        val alias = "ssh_ed25519_${Instant.now().toEpochMilli()}"
        val generator = KeyPairGenerator.getInstance(
            ALGORITHM_ED25519,
            ANDROID_KEY_STORE
        )
        val spec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN
        )
            .setDigests(KeyProperties.DIGEST_NONE)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(
                0,
                KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
            )
            .build()
        generator.initialize(spec)
        val keyPair = generator.generateKeyPair()
        val hardwareBacked = getHardwareBackedStatus(alias)
        val metadata = KeyMetadata(
            alias = alias,
            label = label,
            createdAtEpochMs = Instant.now().toEpochMilli(),
            lastUsedAtEpochMs = null,
            hardwareBacked = hardwareBacked
        )
        store.put(metadata)
        return metadata
    }

    fun listKeys(): List<KeyMetadata> {
        return store.getAll().values.sortedBy { it.createdAtEpochMs }
    }

    fun deleteKey(alias: String) {
        val keyStore = KeyStore.getInstance(ANDROID_KEY_STORE)
        keyStore.load(null)
        if (keyStore.containsAlias(alias)) {
            keyStore.deleteEntry(alias)
        }
        store.remove(alias)
    }

    fun getPublicKey(alias: String): PublicKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEY_STORE)
        keyStore.load(null)
        val cert = keyStore.getCertificate(alias)
            ?: throw IllegalStateException("Missing key for alias: $alias")
        return cert.publicKey
    }

    fun updateLastUsed(alias: String) {
        val current = store.getAll()[alias] ?: return
        store.put(
            current.copy(lastUsedAtEpochMs = Instant.now().toEpochMilli())
        )
    }

    fun getKeyAlgorithm(alias: String): String? {
        val keyStore = KeyStore.getInstance(ANDROID_KEY_STORE)
        keyStore.load(null)
        return keyStore.getCertificate(alias)?.publicKey?.algorithm
    }

    private fun getHardwareBackedStatus(alias: String): Boolean {
        val factory = KeyFactory.getInstance(
            ALGORITHM_ED25519,
            ANDROID_KEY_STORE
        )
        val keyStore = KeyStore.getInstance(ANDROID_KEY_STORE)
        keyStore.load(null)
        val privateKey = keyStore.getKey(alias, null) as? PrivateKey
            ?: return false
        val keyInfo = factory.getKeySpec(privateKey, KeyInfo::class.java) as KeyInfo
        return keyInfo.isInsideSecureHardware
    }

    companion object {
        private const val ANDROID_KEY_STORE = "AndroidKeyStore"
        private const val ALGORITHM_ED25519 = "Ed25519"
    }
}
