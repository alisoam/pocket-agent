package com.example.pocketsshagent.termux

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.os.Binder
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.util.Log
import com.example.pocketsshagent.IPocketAgent
import com.example.pocketsshagent.MainActivity
import com.example.pocketsshagent.agent.AgentCallback
import com.example.pocketsshagent.agent.AgentMessageBuilder
import com.example.pocketsshagent.agent.SshAgentHandler
import com.example.pocketsshagent.agent.SshWireFormat
import com.example.pocketsshagent.crypto.KeyManager
import com.example.pocketsshagent.pairing.TrustStore
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

class TermuxAgentService : Service() {

    companion object {
        private const val TAG = "TermuxAgentService"
        private const val SIGN_CHANNEL_ID = "ssh_sign_requests"
        private const val ENROLL_CHANNEL_ID = "ssh_enroll_requests"
        private const val SIGN_NOTIFICATION_ID = 100
        private const val ENROLL_NOTIFICATION_ID = 101
        const val ACTION_BIND_AGENT = "com.example.pocketsshagent.BIND_TERMUX_AGENT"
        const val ACTION_TERMUX_SIGN_REQUEST = "com.example.pocketsshagent.ACTION_TERMUX_SIGN_REQUEST"
        const val ACTION_TERMUX_CANCEL_SIGN = "com.example.pocketsshagent.ACTION_TERMUX_CANCEL_SIGN"
        const val ACTION_TERMUX_ENROLL_REQUEST = "com.example.pocketsshagent.ACTION_TERMUX_ENROLL_REQUEST"
        const val ACTION_TERMUX_CANCEL_ENROLL = "com.example.pocketsshagent.ACTION_TERMUX_CANCEL_ENROLL"
        private const val SIGN_REQUEST_TIMEOUT_MS = 30_000L
        private const val ENROLL_REQUEST_TIMEOUT_MS = 60_000L
        private const val BINDER_TIMEOUT_SECONDS = 90L
    }

    data class PendingSignRequest(
        val alias: String,
        val keyLabel: String,
        val deviceName: String?,
        val data: ByteArray,
        val onResult: (ByteArray?) -> Unit
    )

    data class PendingEnrollRequest(
        val label: String,
        val alg: String,
        val deviceName: String?,
        val onResult: (Boolean) -> Unit
    )

    private lateinit var trustStore: TrustStore
    private lateinit var keyManager: KeyManager

    private val signingInProgress = AtomicBoolean(false)
    private val enrollInProgress = AtomicBoolean(false)

    private val handlers = mutableMapOf<Int, SshAgentHandler>()

    private val localBinder = LocalBinder()
    @Volatile private var agentCallback: AgentCallback? = null
    @Volatile private var pendingSignRequest: PendingSignRequest? = null
    @Volatile private var pendingEnrollRequest: PendingEnrollRequest? = null

    private val mainHandler = Handler(Looper.getMainLooper())
    private val signTimeoutRunnable = Runnable { cancelPendingSignRequest() }
    private val enrollTimeoutRunnable = Runnable { cancelPendingEnrollRequest() }

    private val agentAidlBinder = object : IPocketAgent.Stub() {
        override fun handleMessage(message: ByteArray): ByteArray {
            val callingPid = Binder.getCallingPid()
            val handler = synchronized(handlers) {
                handlers.getOrPut(callingPid) {
                    createAgentHandler("termux:$callingPid").also { it.forceLocalAuth() }
                }
            }

            val latch = CountDownLatch(1)
            var result = SshWireFormat.frameMessage(AgentMessageBuilder.failure())

            handler.handleMessage(message) { response ->
                result = response
                latch.countDown()
            }

            if (!latch.await(BINDER_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                Log.w(TAG, "handleMessage timed out for pid=$callingPid")
            }
            return result
        }
    }

    inner class LocalBinder : Binder() {
        fun getService(): TermuxAgentService = this@TermuxAgentService
    }

    override fun onBind(intent: Intent?): IBinder {
        return if (intent?.action == ACTION_BIND_AGENT) agentAidlBinder else localBinder
    }

    fun setAgentCallback(callback: AgentCallback) {
        this.agentCallback = callback
    }

    override fun onCreate() {
        super.onCreate()
        trustStore = TrustStore(this)
        keyManager = KeyManager(this)
        createNotificationChannels()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_TERMUX_CANCEL_SIGN) {
            cancelPendingSignRequest()
            return START_NOT_STICKY
        }
        if (intent?.action == ACTION_TERMUX_CANCEL_ENROLL) {
            cancelPendingEnrollRequest()
            return START_NOT_STICKY
        }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        mainHandler.removeCallbacks(signTimeoutRunnable)
        mainHandler.removeCallbacks(enrollTimeoutRunnable)
        cancelPendingSignRequest()
        cancelPendingEnrollRequest()
        synchronized(handlers) { handlers.clear() }
        super.onDestroy()
    }

    private fun createAgentHandler(id: String): SshAgentHandler {
        return SshAgentHandler(keyManager, object : AgentCallback {
            override fun requestBiometricSign(alias: String, keyLabel: String, deviceName: String?, data: ByteArray, onResult: (ByteArray?) -> Unit) {
                val cb = agentCallback
                if (cb != null) {
                    cb.requestBiometricSign(alias, keyLabel, deviceName, data, onResult)
                } else {
                    Log.w(TAG, "No AgentCallback set, denying sign request")
                    onResult(null)
                }
            }
            override fun requestEnrollConfirmation(label: String, alg: String, deviceName: String?, onResult: (Boolean) -> Unit) {
                val cb = agentCallback
                if (cb != null) {
                    cb.requestEnrollConfirmation(label, alg, deviceName, onResult)
                } else {
                    Log.w(TAG, "No AgentCallback set, denying enroll request")
                    onResult(false)
                }
            }
        }, null, signingInProgress, enrollInProgress)
    }

    fun setPendingSignRequest(request: PendingSignRequest) {
        pendingSignRequest = request
        mainHandler.removeCallbacks(signTimeoutRunnable)
        mainHandler.postDelayed(signTimeoutRunnable, SIGN_REQUEST_TIMEOUT_MS)
    }

    fun consumePendingSignRequest(): PendingSignRequest? {
        mainHandler.removeCallbacks(signTimeoutRunnable)
        val req = pendingSignRequest
        pendingSignRequest = null
        if (req != null) {
            getSystemService(NotificationManager::class.java).cancel(SIGN_NOTIFICATION_ID)
        }
        return req
    }

    private fun cancelPendingSignRequest() {
        mainHandler.removeCallbacks(signTimeoutRunnable)
        val req = pendingSignRequest
        pendingSignRequest = null
        getSystemService(NotificationManager::class.java).cancel(SIGN_NOTIFICATION_ID)
        if (req != null) {
            Log.d(TAG, "Pending sign request cancelled")
            req.onResult(null)
        }
    }

    fun setPendingEnrollRequest(request: PendingEnrollRequest) {
        pendingEnrollRequest = request
        mainHandler.removeCallbacks(enrollTimeoutRunnable)
        mainHandler.postDelayed(enrollTimeoutRunnable, ENROLL_REQUEST_TIMEOUT_MS)
    }

    fun consumePendingEnrollRequest(): PendingEnrollRequest? {
        mainHandler.removeCallbacks(enrollTimeoutRunnable)
        val req = pendingEnrollRequest
        pendingEnrollRequest = null
        if (req != null) {
            getSystemService(NotificationManager::class.java).cancel(ENROLL_NOTIFICATION_ID)
        }
        return req
    }

    private fun cancelPendingEnrollRequest() {
        mainHandler.removeCallbacks(enrollTimeoutRunnable)
        val req = pendingEnrollRequest
        pendingEnrollRequest = null
        getSystemService(NotificationManager::class.java).cancel(ENROLL_NOTIFICATION_ID)
        if (req != null) {
            Log.d(TAG, "Pending enroll request cancelled")
            req.onResult(false)
        }
    }

    fun postSignNotification(keyLabel: String, deviceName: String?) {
        val tapIntent = Intent(this, MainActivity::class.java).apply {
            action = ACTION_TERMUX_SIGN_REQUEST
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_NEW_TASK
        }
        val tapPi = PendingIntent.getActivity(
            this, 10, tapIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val cancelPi = PendingIntent.getService(
            this, 10,
            Intent(this, TermuxAgentService::class.java).apply { action = ACTION_TERMUX_CANCEL_SIGN },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val contentText = if (deviceName != null) "Termux ($deviceName) wants to sign with: $keyLabel" else "Termux wants to sign with: $keyLabel"
        val notification = Notification.Builder(this, SIGN_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle("SSH Sign Request (Termux)")
            .setContentText(contentText)
            .setContentIntent(tapPi)
            .setDeleteIntent(cancelPi)
            .setAutoCancel(true)
            .setPriority(Notification.PRIORITY_HIGH)
            .build()
        getSystemService(NotificationManager::class.java).notify(SIGN_NOTIFICATION_ID, notification)
    }

    fun postEnrollNotification(label: String, deviceName: String?) {
        val tapIntent = Intent(this, MainActivity::class.java).apply {
            action = ACTION_TERMUX_ENROLL_REQUEST
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_NEW_TASK
        }
        val tapPi = PendingIntent.getActivity(
            this, 11, tapIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val cancelPi = PendingIntent.getService(
            this, 11,
            Intent(this, TermuxAgentService::class.java).apply { action = ACTION_TERMUX_CANCEL_ENROLL },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val contentText = if (deviceName != null) "Termux ($deviceName) wants to create key: $label" else "Termux wants to create key: $label"
        val notification = Notification.Builder(this, ENROLL_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle("New SSH Key Request (Termux)")
            .setContentText(contentText)
            .setContentIntent(tapPi)
            .setDeleteIntent(cancelPi)
            .setAutoCancel(true)
            .setPriority(Notification.PRIORITY_HIGH)
            .build()
        getSystemService(NotificationManager::class.java).notify(ENROLL_NOTIFICATION_ID, notification)
    }

    private fun createNotificationChannels() {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel(
                SIGN_CHANNEL_ID,
                "SSH Sign Requests",
                NotificationManager.IMPORTANCE_HIGH
            ).apply { description = "Tap to approve SSH signing requests" }
        )
        nm.createNotificationChannel(
            NotificationChannel(
                ENROLL_CHANNEL_ID,
                "SSH Key Creation Requests",
                NotificationManager.IMPORTANCE_HIGH
            ).apply { description = "Tap to approve or deny new SSH key creation" }
        )
    }
}
