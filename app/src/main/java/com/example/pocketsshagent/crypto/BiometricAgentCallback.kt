package com.example.pocketsshagent.crypto

import android.util.Log
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import com.example.pocketsshagent.agent.AgentCallback
import com.example.pocketsshagent.agent.SshWireFormat
import com.example.pocketsshagent.ble.BleAgentService
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature

class BiometricAgentCallback(
    private val activity: FragmentActivity,
    private val service: BleAgentService
) : AgentCallback {

    companion object {
        private const val TAG = "BiometricAgentCallback"
        private const val ANDROID_KEY_STORE = "AndroidKeyStore"
    }

    override fun requestBiometricSign(alias: String, keyLabel: String, deviceName: String?, data: ByteArray, onResult: (ByteArray?) -> Unit) {
        activity.runOnUiThread {
            if (activity.lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) {
                showBiometricPrompt(alias, keyLabel, deviceName, data, onResult)
            } else {
                Log.d(TAG, "App not in foreground, posting sign notification for: $alias")
                service.setPendingSignRequest(BleAgentService.PendingSignRequest(alias, keyLabel, deviceName, data, onResult))
                service.postSignNotification(keyLabel, deviceName)
            }
        }
    }

    fun resumePendingSign() {
        val req = service.consumePendingSignRequest() ?: return
        Log.d(TAG, "Resuming pending sign request for: ${req.alias}")
        showBiometricPrompt(req.alias, req.keyLabel, req.deviceName, req.data, req.onResult)
    }

    private fun showBiometricPrompt(alias: String, keyLabel: String, deviceName: String?, data: ByteArray, onResult: (ByteArray?) -> Unit) {
        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEY_STORE)
            keyStore.load(null)

            val privateKey = keyStore.getKey(alias, null) as? PrivateKey
                ?: run {
                    Log.e(TAG, "Key not found: $alias")
                    onResult(null)
                    return
                }

            // Determine signing algorithm from the public key's X.509 OID.
            // NONEwithECDSA for P-256: the proxy pre-hashes data to SHA-256 before
            // sending, so we always sign raw (no re-hashing on Android).
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

            val description = if (deviceName != null) "Requested by: $deviceName" else "An SSH client is requesting a signature."
            val promptInfo = BiometricPrompt.PromptInfo.Builder()
                .setTitle("SSH Signing Request")
                .setSubtitle("Sign with key: $keyLabel")
                .setDescription(description)
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
