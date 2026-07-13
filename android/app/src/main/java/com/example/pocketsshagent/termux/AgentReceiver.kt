package com.example.pocketsshagent.termux

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Binder
import android.util.Base64
import android.util.Log
import com.example.pocketsshagent.agent.AgentCallback
import com.example.pocketsshagent.agent.AgentMessageBuilder
import com.example.pocketsshagent.crypto.SessionCrypto
import com.example.pocketsshagent.data.SettingsStore
import com.example.pocketsshagent.agent.SshAgentHandler
import com.example.pocketsshagent.agent.SshWireFormat
import com.example.pocketsshagent.crypto.KeyManager
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.spec.X509EncodedKeySpec
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.KeyAgreement

class AgentReceiver : BroadcastReceiver() {

    companion object {
        private const val TAG = "AgentReceiver"
        private const val TIMEOUT_SECONDS = 90L
        private val operationInProgress = AtomicBoolean(false)
        private const val TERMUX_HKDF_INFO = "pocket-ssh-termux-v1"
    }

    override fun onReceive(context: Context, intent: Intent) {
        if (!SettingsStore(context.applicationContext).termuxEnabled) {
            Log.i(TAG, "Termux service disabled, rejecting request")
            resultCode = Activity.RESULT_CANCELED
            return
        }

        val callingUid = Binder.getCallingUid()
        if (!TermuxIdentity.isCallerTermux(context, callingUid)) {
            resultCode = Activity.RESULT_CANCELED
            return
        }

        val msgB64 = intent.getStringExtra("msg")
        if (msgB64 == null) {
            resultCode = Activity.RESULT_CANCELED
            return
        }

        val dhB64 = intent.getStringExtra("dh")
        if (dhB64 == null) {
            Log.w(TAG, "Missing dh extra, rejecting")
            resultCode = Activity.RESULT_CANCELED
            return
        }

        val clientDhPubRaw = try {
            Base64.decode(dhB64, Base64.NO_WRAP)
        } catch (e: Exception) {
            Log.e(TAG, "Invalid dh base64", e)
            resultCode = Activity.RESULT_CANCELED
            return
        }

        val message = try {
            Base64.decode(msgB64, Base64.NO_WRAP)
        } catch (e: Exception) {
            Log.e(TAG, "Invalid base64", e)
            resultCode = Activity.RESULT_CANCELED
            return
        }

        Log.i(TAG, "Received agent request (${message.size} bytes)")

        val pendingResult = goAsync()

        Thread {
            try {
                val keyManager = KeyManager(context.applicationContext)
                val handler = createHandler(keyManager)
                handler.forceLocalAuth()

                val latch = CountDownLatch(1)
                var response = SshWireFormat.frameMessage(AgentMessageBuilder.failure())

                handler.handleMessage(message) { resp ->
                    response = resp
                    latch.countDown()
                }

                if (!latch.await(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                    Log.w(TAG, "handleMessage timed out")
                }

                val result = try {
                    encryptResponse(clientDhPubRaw, response)
                } catch (e: Exception) {
                    Log.e(TAG, "Encryption failed, sending failure in plaintext", e)
                    response
                }

                val responseB64 = Base64.encodeToString(result, Base64.NO_WRAP)
                pendingResult.resultCode = Activity.RESULT_OK
                pendingResult.resultData = responseB64
            } catch (e: Exception) {
                Log.e(TAG, "Error processing message", e)
                pendingResult.resultCode = Activity.RESULT_CANCELED
            } finally {
                pendingResult.finish()
            }
        }.start()
    }

    private fun encryptResponse(clientPubRaw: ByteArray, plaintext: ByteArray): ByteArray {
        val kpg = KeyPairGenerator.getInstance("X25519")
        val keyPair = kpg.generateKeyPair()
        val ourPubRaw = keyPair.public.encoded.copyOfRange(12, 44)

        val proxyPub = KeyFactory.getInstance("X25519")
            .generatePublic(X509EncodedKeySpec(SessionCrypto.X25519_SPKI_HEADER + clientPubRaw))

        val ka = KeyAgreement.getInstance("X25519")
        ka.init(keyPair.private)
        ka.doPhase(proxyPub, true)
        val sharedSecret = ka.generateSecret()

        val info = TERMUX_HKDF_INFO.toByteArray(Charsets.US_ASCII)
        val sessionKey = SessionCrypto.hkdfSha256(sharedSecret, ByteArray(32), info)

        val encrypted = SessionCrypto.sealWithKey(sessionKey, plaintext)
        return ourPubRaw + encrypted
    }

    private fun createHandler(keyManager: KeyManager): SshAgentHandler {
        return SshAgentHandler(keyManager, object : AgentCallback {
            override fun requestBiometricSign(alias: String, keyLabel: String, deviceName: String?, data: ByteArray, onResult: (ByteArray?) -> Unit) {
                val cb = AgentContentProvider.agentCallback
                if (cb != null) {
                    cb.requestBiometricSign(alias, keyLabel, "Termux", data, onResult)
                } else {
                    Log.w(TAG, "No AgentCallback set, denying sign")
                    onResult(null)
                }
            }
            override fun requestEnrollConfirmation(label: String, alg: String, deviceName: String?, onResult: (Boolean) -> Unit) {
                val cb = AgentContentProvider.agentCallback
                if (cb != null) {
                    cb.requestEnrollConfirmation(label, alg, "Termux", onResult)
                } else {
                    Log.w(TAG, "No AgentCallback set, denying enroll")
                    onResult(false)
                }
            }
            override fun requestResidentKeysAccess(count: Int, deviceName: String?, onResult: (Boolean) -> Unit) {
                val cb = AgentContentProvider.agentCallback
                if (cb != null) {
                    cb.requestResidentKeysAccess(count, deviceName ?: "Termux", onResult)
                } else {
                    Log.w(TAG, "No AgentCallback set, denying resident key access")
                    onResult(false)
                }
            }
        }, null, operationInProgress)
    }
}
