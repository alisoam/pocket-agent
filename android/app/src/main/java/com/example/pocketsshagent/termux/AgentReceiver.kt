package com.example.pocketsshagent.termux

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Base64
import android.util.Log
import com.example.pocketsshagent.agent.AgentCallback
import com.example.pocketsshagent.agent.AgentMessageBuilder
import com.example.pocketsshagent.agent.SshAgentHandler
import com.example.pocketsshagent.agent.SshWireFormat
import com.example.pocketsshagent.crypto.KeyManager
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

class AgentReceiver : BroadcastReceiver() {

    companion object {
        private const val TAG = "AgentReceiver"
        private const val TIMEOUT_SECONDS = 90L
        private val signingInProgress = AtomicBoolean(false)
        private val enrollInProgress = AtomicBoolean(false)
    }

    override fun onReceive(context: Context, intent: Intent) {
        val msgB64 = intent.getStringExtra("msg")
        if (msgB64 == null) {
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

                val responseB64 = Base64.encodeToString(response, Base64.NO_WRAP)
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
        }, null, signingInProgress, enrollInProgress)
    }
}
