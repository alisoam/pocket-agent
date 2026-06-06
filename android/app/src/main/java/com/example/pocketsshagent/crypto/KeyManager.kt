package com.example.pocketsshagent.crypto

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import com.example.pocketsshagent.data.KeyMetadataStore
import com.example.pocketsshagent.model.KeyMetadata
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.ECGenParameterSpec
import java.time.Instant

class KeyManager(private val context: Context) {
    private val store = KeyMetadataStore(context)

    fun generateKey(label: String): KeyMetadata = generateKey(label, isEcdsa = false)

    fun generateKey(label: String, isEcdsa: Boolean): KeyMetadata {
        val alias = if (isEcdsa) "ec_${Instant.now().toEpochMilli()}"
                    else "ssh_ed25519_${Instant.now().toEpochMilli()}"

        val generator: KeyPairGenerator
        if (isEcdsa) {
            generator = KeyPairGenerator.getInstance("EC", ANDROID_KEY_STORE)
            generator.initialize(
                KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_NONE, KeyProperties.DIGEST_SHA256)
                    .setUserAuthenticationRequired(true)
                    .setUserAuthenticationParameters(
                        0,
                        KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
                    )
                    .build()
            )
        } else {
            generator = KeyPairGenerator.getInstance(ALGORITHM_ED25519, ANDROID_KEY_STORE)
            generator.initialize(
                KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                    .setDigests(KeyProperties.DIGEST_NONE, KeyProperties.DIGEST_SHA256)
                    .setUserAuthenticationRequired(true)
                    .setUserAuthenticationParameters(
                        0,
                        KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
                    )
                    .build()
            )
        }
        generator.generateKeyPair()

        val hardwareBacked = getHardwareBackedStatus(alias)
        val metadata = KeyMetadata(
            alias = alias,
            label = label,
            createdAtEpochMs = Instant.now().toEpochMilli(),
            lastUsedAtEpochMs = null,
            hardwareBacked = hardwareBacked
        )
        store.put(metadata)
        notifyChanged()
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
        notifyChanged()
    }

    fun getPublicKey(alias: String): PublicKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEY_STORE)
        keyStore.load(null)
        val cert = keyStore.getCertificate(alias)
            ?: throw IllegalStateException("Missing key for alias: $alias")
        return cert.publicKey
    }

    fun renameKey(alias: String, newLabel: String) {
        val current = store.getAll()[alias] ?: return
        store.put(current.copy(label = newLabel))
        notifyChanged()
    }

    fun updateLastUsed(alias: String) {
        val current = store.getAll()[alias] ?: return
        store.put(
            current.copy(lastUsedAtEpochMs = Instant.now().toEpochMilli())
        )
    }

    /** Atomically increments and persists the FIDO2 counter for an SK key. Returns the new value. */
    @Synchronized
    fun incrementSkCounter(alias: String): Long {
        val current = store.getAll()[alias] ?: return 0
        val newCounter = current.skCounter + 1
        store.put(current.copy(skCounter = newCounter))
        return newCounter
    }

    fun getKeyAlgorithm(alias: String): String? {
        val keyStore = KeyStore.getInstance(ANDROID_KEY_STORE)
        keyStore.load(null)
        return keyStore.getCertificate(alias)?.publicKey?.algorithm
    }

    private fun getHardwareBackedStatus(alias: String): Boolean {
        val keyStore = KeyStore.getInstance(ANDROID_KEY_STORE)
        keyStore.load(null)
        val privateKey = keyStore.getKey(alias, null) as? PrivateKey ?: return false
        val algorithm = privateKey.algorithm.let {
            // Android may report "EdDSA" instead of "Ed25519" on some versions
            if (it == "EdDSA") ALGORITHM_ED25519 else it
        }
        return try {
            val factory = KeyFactory.getInstance(algorithm, ANDROID_KEY_STORE)
            val keyInfo = factory.getKeySpec(privateKey, KeyInfo::class.java) as KeyInfo
            keyInfo.isInsideSecureHardware
        } catch (_: Exception) {
            false
        }
    }

    companion object {
        private const val ANDROID_KEY_STORE = "AndroidKeyStore"
        private const val ALGORITHM_ED25519 = "Ed25519"

        private val _keysVersion = MutableStateFlow(0)
        val keysVersion: StateFlow<Int> = _keysVersion

        internal fun notifyChanged() { _keysVersion.value++ }
    }
}
