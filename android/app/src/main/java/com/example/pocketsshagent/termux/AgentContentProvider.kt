package com.example.pocketsshagent.termux

import android.content.ContentProvider
import android.content.ContentValues
import android.content.pm.PackageManager
import android.database.Cursor
import android.net.Uri
import android.os.Binder
import android.os.Bundle
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

class AgentContentProvider : ContentProvider() {

    companion object {
        private const val TAG = "AgentContentProvider"
        private const val TIMEOUT_SECONDS = 90L

        @Volatile var agentCallback: AgentCallback? = null

        val operationInProgress = AtomicBoolean(false)

        @Volatile var pendingSignRequest: PendingSignRequest? = null
        @Volatile var pendingEnrollRequest: PendingEnrollRequest? = null
    }

    data class PendingSignRequest(
        val alias: String,
        val keyLabel: String,
        val appName: String?,
        val data: ByteArray,
        val onResult: (ByteArray?) -> Unit
    )

    data class PendingEnrollRequest(
        val label: String,
        val alg: String,
        val appName: String?,
        val onResult: (Boolean) -> Unit
    )

    private lateinit var keyManager: KeyManager
    private val handlers = mutableMapOf<Int, SshAgentHandler>()

    override fun onCreate(): Boolean {
        keyManager = KeyManager(context!!)
        return true
    }

    override fun call(method: String, arg: String?, extras: Bundle?): Bundle? {
        if (method != "handleMessage" || arg == null) return null

        val message = try {
            Base64.decode(arg, Base64.NO_WRAP)
        } catch (e: Exception) {
            Log.e(TAG, "Invalid base64 argument", e)
            return null
        }

        val callingUid = Binder.getCallingUid()
        val appName = resolveAppName(callingUid)
        Log.i(TAG, "Request from $appName (UID $callingUid)")

        val handler = synchronized(handlers) {
            handlers.getOrPut(callingUid) {
                createAgentHandler(appName).also { it.forceLocalAuth() }
            }
        }

        val latch = CountDownLatch(1)
        var result = SshWireFormat.frameMessage(AgentMessageBuilder.failure())

        handler.handleMessage(message) { response ->
            result = response
            latch.countDown()
        }

        if (!latch.await(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
            Log.w(TAG, "handleMessage timed out for $appName")
        }

        val responseB64 = Base64.encodeToString(result, Base64.NO_WRAP)
        return Bundle().apply { putString("r", responseB64) }
    }

    private fun resolveAppName(uid: Int): String {
        val pm = context?.packageManager ?: return "UID $uid"
        return try {
            val packageName = pm.getNameForUid(uid) ?: return "UID $uid"
            val appInfo = pm.getApplicationInfo(packageName, 0)
            pm.getApplicationLabel(appInfo).toString()
        } catch (e: PackageManager.NameNotFoundException) {
            "UID $uid"
        }
    }

    private fun createAgentHandler(appName: String): SshAgentHandler {
        return SshAgentHandler(keyManager, object : AgentCallback {
            override fun requestBiometricSign(alias: String, keyLabel: String, deviceName: String?, data: ByteArray, onResult: (ByteArray?) -> Unit) {
                val cb = agentCallback
                if (cb != null) {
                    cb.requestBiometricSign(alias, keyLabel, appName, data, onResult)
                } else {
                    Log.w(TAG, "No AgentCallback set, denying sign from $appName")
                    onResult(null)
                }
            }
            override fun requestEnrollConfirmation(label: String, alg: String, deviceName: String?, onResult: (Boolean) -> Unit) {
                val cb = agentCallback
                if (cb != null) {
                    cb.requestEnrollConfirmation(label, alg, appName, onResult)
                } else {
                    Log.w(TAG, "No AgentCallback set, denying enroll from $appName")
                    onResult(false)
                }
            }
        }, null, operationInProgress)
    }

    override fun query(uri: Uri, projection: Array<out String>?, selection: String?, selectionArgs: Array<out String>?, sortOrder: String?): Cursor? = null
    override fun getType(uri: Uri): String? = null
    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?): Int = 0
}
