package com.example.pocketsshagent.crypto

import android.util.Log
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.example.pocketsshagent.agent.AgentCallback
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature

/**
 * AgentCallback implementation that uses BiometricPrompt to authorize
 * every signing operation. The Keystore key requires user authentication,
 * so the BiometricPrompt's CryptoObject unlocks it for a single use.
 */
class BiometricAgentCallback(
    private val activity: FragmentActivity
) : AgentCallback {

    companion object {
        private const val TAG = "BiometricAgentCallback"
        private const val ANDROID_KEY_STORE = "AndroidKeyStore"
    }

    override fun requestBiometricSign(alias: String, data: ByteArray, onResult: (ByteArray?) -> Unit) {
        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEY_STORE)
            keyStore.load(null)
            val privateKey = keyStore.getKey(alias, null) as? PrivateKey
                ?: run {
                    Log.e(TAG, "Key not found: $alias")
                    onResult(null)
                    return
                }

            // Initialize signature — this will require biometric auth
            val signature = Signature.getInstance("Ed25519")
            signature.initSign(privateKey)

            val cryptoObject = BiometricPrompt.CryptoObject(signature)

            val executor = ContextCompat.getMainExecutor(activity)
            val biometricPrompt = BiometricPrompt(activity, executor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        try {
                            val authedSignature = result.cryptoObject?.signature
                                ?: run {
                                    Log.e(TAG, "CryptoObject missing after auth")
                                    onResult(null)
                                    return
                                }
                            authedSignature.update(data)
                            val signed = authedSignature.sign()
                            Log.d(TAG, "Signing succeeded for alias: $alias")
                            onResult(signed)
                        } catch (e: Exception) {
                            Log.e(TAG, "Signing failed after auth", e)
                            onResult(null)
                        }
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        Log.w(TAG, "Biometric auth error [$errorCode]: $errString")
                        onResult(null)
                    }

                    override fun onAuthenticationFailed() {
                        Log.w(TAG, "Biometric auth failed (bad finger/face)")
                        // Don't call onResult — the system allows retries
                    }
                }
            )

            val promptInfo = BiometricPrompt.PromptInfo.Builder()
                .setTitle("SSH Signing Request")
                .setSubtitle("Approve to sign with key: $alias")
                .setDescription("An SSH client is requesting a signature.")
                .setAllowedAuthenticators(
                    androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG or
                            androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
                )
                .build()

            biometricPrompt.authenticate(promptInfo, cryptoObject)

        } catch (e: Exception) {
            Log.e(TAG, "Failed to initiate biometric sign", e)
            onResult(null)
        }
    }
}
