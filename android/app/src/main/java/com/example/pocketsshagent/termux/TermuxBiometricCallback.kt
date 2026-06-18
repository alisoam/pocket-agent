package com.example.pocketsshagent.termux

import android.util.Log
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import com.example.pocketsshagent.agent.AgentCallback
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature

class TermuxBiometricCallback(
    private val activity: FragmentActivity,
    private val service: TermuxAgentService
) : AgentCallback {

    companion object {
        private const val TAG = "TermuxBiometricCb"
        private const val ANDROID_KEY_STORE = "AndroidKeyStore"
    }

    override fun requestBiometricSign(alias: String, keyLabel: String, deviceName: String?, data: ByteArray, onResult: (ByteArray?) -> Unit) {
        activity.runOnUiThread {
            if (activity.lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) {
                showBiometricPrompt(alias, keyLabel, deviceName, data, onResult)
            } else {
                Log.d(TAG, "App not in foreground, posting sign notification for: $alias")
                service.setPendingSignRequest(TermuxAgentService.PendingSignRequest(alias, keyLabel, deviceName, data, onResult))
                service.postSignNotification(keyLabel, deviceName)
            }
        }
    }

    override fun requestEnrollConfirmation(label: String, alg: String, deviceName: String?, onResult: (Boolean) -> Unit) {
        activity.runOnUiThread {
            if (activity.lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) {
                showEnrollDialog(label, alg, deviceName, onResult)
            } else {
                Log.d(TAG, "App not in foreground, posting enroll notification for: $label")
                service.setPendingEnrollRequest(TermuxAgentService.PendingEnrollRequest(label, alg, deviceName, onResult))
                service.postEnrollNotification(label, deviceName)
            }
        }
    }

    fun resumePendingSign() {
        val req = service.consumePendingSignRequest() ?: return
        Log.d(TAG, "Resuming pending sign request for: ${req.alias}")
        showBiometricPrompt(req.alias, req.keyLabel, req.deviceName, req.data, req.onResult)
    }

    fun resumePendingEnroll() {
        val req = service.consumePendingEnrollRequest() ?: return
        Log.d(TAG, "Resuming pending enroll request for: ${req.label}")
        showEnrollDialog(req.label, req.alg, req.deviceName, req.onResult)
    }

    override fun requestResidentKeysAccess(count: Int, deviceName: String?, onResult: (Boolean) -> Unit) {
        activity.runOnUiThread {
            if (activity.lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) {
                showResidentAccessDialog(count, deviceName, onResult)
            } else {
                Log.d(TAG, "App not in foreground, posting resident access notification")
                service.setPendingResidentAccessRequest(TermuxAgentService.PendingResidentAccessRequest(count, deviceName, onResult))
                service.postResidentAccessNotification(count, deviceName)
            }
        }
    }

    fun resumePendingResidentAccess() {
        val req = service.consumePendingResidentAccessRequest() ?: return
        Log.d(TAG, "Resuming pending resident access request")
        showResidentAccessDialog(req.count, req.deviceName, req.onResult)
    }

    private fun showResidentAccessDialog(count: Int, deviceName: String?, onResult: (Boolean) -> Unit) {
        val message = buildString {
            append("Allow downloading $count resident key(s)?")
            if (deviceName != null) append("\n\nRequested by: $deviceName")
        }
        android.app.AlertDialog.Builder(activity)
            .setTitle("Resident Key Access")
            .setMessage(message)
            .setPositiveButton("Allow") { _, _ -> onResult(true) }
            .setNegativeButton("Deny") { _, _ -> onResult(false) }
            .setOnCancelListener { onResult(false) }
            .show()
    }

    private fun showEnrollDialog(label: String, alg: String, deviceName: String?, onResult: (Boolean) -> Unit) {
        val message = buildString {
            append("Allow generating a new $alg key?\n\nLabel: $label")
            if (deviceName != null) append("\nRequested by: $deviceName")
        }
        android.app.AlertDialog.Builder(activity)
            .setTitle("New SSH Key Request")
            .setMessage(message)
            .setPositiveButton("Allow") { _, _ -> onResult(true) }
            .setNegativeButton("Deny") { _, _ -> onResult(false) }
            .setOnCancelListener { onResult(false) }
            .show()
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

            val sigAlgo = when (privateKey.algorithm) {
                "EC" -> "NONEwithECDSA"
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

            val description = if (deviceName != null) "Requested by: $deviceName" else "Termux is requesting a signature."
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
