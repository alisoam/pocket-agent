package com.example.pocketsshagent.termux

import android.content.ContentProvider
import android.content.ContentValues
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.database.Cursor
import android.net.Uri
import android.os.Binder
import android.os.Bundle
import android.os.SystemClock
import android.util.Base64
import android.util.Log
import com.example.pocketsshagent.agent.AgentCallback
import com.example.pocketsshagent.agent.AgentMessageBuilder
import com.example.pocketsshagent.agent.SshAgentHandler
import com.example.pocketsshagent.agent.SshWireFormat
import com.example.pocketsshagent.crypto.KeyManager
import com.example.pocketsshagent.crypto.SessionCrypto
import com.example.pocketsshagent.data.SettingsStore
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Authenticated, asynchronous agent channel for local CLI callers (Termux).
 *
 * Two methods, both reachable via `content call`:
 *   - "initiate": authorize the caller, start handling the request (which may
 *     trigger an async biometric prompt), and return immediately with a random
 *     `requestId` plus a fresh per-request AES-256 key.
 *   - "poll": return "pending" until the result is ready, then the AES-GCM
 *     encrypted response (single use).
 *
 * Why this shape:
 *   - `content call` is a binder transaction, so `Binder.getCallingUid()` is
 *     trustworthy and we can enforce a caller allowlist (Termux only).
 *   - Decoupling initiate from poll removes any synchronous binder blocking, so
 *     the user has unlimited time to foreground the app and authenticate.
 *   - The `requestId` is an unguessable capability token returned only to the
 *     authenticated initiator, and is the gate on the poll path; the per-request
 *     key keeps the response (notably resident-key listings) confidential.
 */
class AgentContentProvider : ContentProvider() {

    companion object {
        private const val TAG = "AgentContentProvider"

        /** Packages permitted to call the agent. Hardcoded to Termux for now. */
        private val ALLOWED_PACKAGES = setOf("com.termux")

        /** Pending results are discarded if not polled within this window. */
        private const val REQUEST_TTL_MS = 120_000L

        @Volatile var agentCallback: AgentCallback? = null

        val operationInProgress = AtomicBoolean(false)
    }

    private class ResultSlot(val callingUid: Int, val createdAt: Long) {
        @Volatile var done: Boolean = false
        @Volatile var encrypted: ByteArray? = null
    }

    private lateinit var keyManager: KeyManager
    private val slots = ConcurrentHashMap<String, ResultSlot>()
    private val executor = Executors.newCachedThreadPool()
    private val secureRandom = SecureRandom()

    override fun onCreate(): Boolean {
        keyManager = KeyManager(context!!)
        return true
    }

    override fun call(method: String, arg: String?, extras: Bundle?): Bundle? {
        val callingUid = Binder.getCallingUid()
        if (!isAuthorized(callingUid)) {
            Log.w(TAG, "Rejected unauthorized call (method=$method, uid=$callingUid)")
            return Bundle().apply { putString("e", "unauthorized") }
        }

        pruneExpired()

        return when (method) {
            "initiate" -> handleInitiate(arg, callingUid)
            "poll" -> handlePoll(arg, callingUid)
            else -> null
        }
    }

    private fun handleInitiate(arg: String?, callingUid: Int): Bundle {
        val message = arg?.let {
            try {
                Base64.decode(it, Base64.NO_WRAP)
            } catch (e: Exception) {
                Log.e(TAG, "Invalid base64 argument", e)
                null
            }
        } ?: return Bundle().apply { putString("e", "bad_request") }

        val requestId = randomHex(16)
        val key = ByteArray(32).also { secureRandom.nextBytes(it) }
        val crypto = SessionCrypto.withRawKey(key)
        val slot = ResultSlot(callingUid, SystemClock.elapsedRealtime())
        slots[requestId] = slot

        val appName = resolveAppName(callingUid)
        val handler = createAgentHandler(appName).also { it.forceLocalAuth() }

        executor.execute {
            try {
                handler.handleMessage(message) { response ->
                    slot.encrypted = crypto.seal(response)
                    slot.done = true
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error handling message for $appName", e)
                slot.encrypted = crypto.seal(SshWireFormat.frameMessage(AgentMessageBuilder.failure()))
                slot.done = true
            }
        }

        return Bundle().apply {
            putString("id", requestId)
            putString("k", Base64.encodeToString(key, Base64.NO_WRAP))
        }
    }

    private fun handlePoll(arg: String?, callingUid: Int): Bundle {
        val requestId = arg ?: return Bundle().apply { putString("s", "unknown") }
        val slot = slots[requestId]
        // Treat a foreign uid the same as a missing id: never leak existence.
        if (slot == null || slot.callingUid != callingUid) {
            return Bundle().apply { putString("s", "unknown") }
        }
        if (!slot.done) {
            return Bundle().apply { putString("s", "pending") }
        }
        slots.remove(requestId) // single use
        return Bundle().apply {
            putString("s", "done")
            putString("d", Base64.encodeToString(slot.encrypted, Base64.NO_WRAP))
        }
    }

    private fun isAuthorized(uid: Int): Boolean {
        val ctx = context ?: return false
        if (!SettingsStore(ctx).termuxEnabled) return false
        val packages = ctx.packageManager.getPackagesForUid(uid) ?: return false
        if (packages.any { it in ALLOWED_PACKAGES }) return true
        // Debug builds also accept `adb shell content call` for local testing.
        val debuggable = (ctx.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
        return debuggable && packages.any { it == "com.android.shell" }
    }

    private fun pruneExpired() {
        val now = SystemClock.elapsedRealtime()
        slots.entries.removeIf { now - it.value.createdAt > REQUEST_TTL_MS }
    }

    private fun randomHex(numBytes: Int): String {
        val bytes = ByteArray(numBytes).also { secureRandom.nextBytes(it) }
        return bytes.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
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
            override fun requestResidentKeysAccess(count: Int, deviceName: String?, onResult: (Boolean) -> Unit) {
                val cb = agentCallback
                if (cb != null) {
                    cb.requestResidentKeysAccess(count, appName, onResult)
                } else {
                    Log.w(TAG, "No AgentCallback set, denying resident key access from $appName")
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
