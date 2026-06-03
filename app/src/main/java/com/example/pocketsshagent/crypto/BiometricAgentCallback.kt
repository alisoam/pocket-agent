package com.example.pocketsshagent.crypto

import android.util.Log
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.example.pocketsshagent.agent.AgentCallback
import com.example.pocketsshagent.agent.SshWireFormat
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature

class BiometricAgentCallback(
    private val activity: FragmentActivity
) : AgentCallback {

    companion object {
        private const val TAG = "BiometricAgentCallback"
        private const val ANDROID_KEY_STORE = "AndroidKeyStore"
    }

    override fun requestBiometricSign(alias: String, data: ByteArray, onResult: (ByteArray?) -> Unit) {
        activity.runOnUiThread {
            try {
                val keyStore = KeyStore.getInstance(ANDROID_KEY_STORE)
                keyStore.load(null)

                val privateKey = keyStore.getKey(alias, null) as? PrivateKey
                    ?: run {
                        Log.e(TAG, "Key not found: $alias")
                        onResult(null)
                        return@runOnUiThread
                    }

                // Determine signing algorithm from the public key's X.509 OID.
                // NONEwithECDSA for P-256: OpenSSH sends a pre-hashed SHA-256 digest
                // via PKCS#11 CKM_ECDSA, so we sign raw without re-hashing.
                val pubEncoded = keyStore.getCertificate(alias)?.publicKey?.encoded
                val sigAlgo = when {
                    pubEncoded != null && SshWireFormat.isP256PublicKey(pubEncoded) -> "NONEwithECDSA"
                    else -> "Ed25519"
                }
                Log.d(TAG, "Signing with $sigAlgo for alias $alias")

                val signature = Signature.getInstance(sigAlgo)
                signature.initSign(privateKey)

                val cryptoObject = BiometricPrompt.CryptoObject(signature)
                val executor = ContextCompat.getMainExecutor(activity)

                val biometricPrompt = BiometricPrompt(activity, executor,
                    object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                            try {
                                val authedSig = result.cryptoObject?.signature
                                    ?: run {
                                        Log.e(TAG, "CryptoObject missing after auth")
                                        onResult(null)
                                        return
                                    }
                                authedSig.update(data)
                                val signed = authedSig.sign()
                                Log.d(TAG, "Signing succeeded ($sigAlgo) for alias: $alias, sigLen=${signed.size}")
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
}
