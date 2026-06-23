package com.example.pocketsshagent.ble

import android.annotation.SuppressLint
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.BluetoothLeAdvertiser
import android.bluetooth.BluetoothAdapter
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import com.example.pocketsshagent.MainActivity
import android.os.Binder
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.ParcelUuid
import android.util.Log
import com.example.pocketsshagent.agent.AgentCallback
import com.example.pocketsshagent.agent.SshAgentHandler
import com.example.pocketsshagent.agent.SshWireFormat
import com.example.pocketsshagent.crypto.KeyManager
import com.example.pocketsshagent.pairing.TrustStore
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Foreground service that runs a BLE GATT server implementing the SSH agent protocol.
 *
 * Clients (desktop proxy) connect via BLE, write agent requests to the RX characteristic,
 * and receive responses via notifications on the TX characteristic.
 */
// BLE advertise/connect permissions are requested and enforced in MainActivity
// before this service is ever started; lint can't see that cross-class guarantee.
@SuppressLint("MissingPermission")
class BleAgentService : Service() {

    companion object {
        private const val TAG = "BleAgentService"
        private const val NOTIFICATION_CHANNEL_ID = "ssh_agent_channel"
        private const val SIGN_CHANNEL_ID = "ssh_sign_requests"
        private const val ENROLL_CHANNEL_ID = "ssh_enroll_requests"
        private const val NOTIFICATION_ID = 1
        private const val SIGN_NOTIFICATION_ID = 2
        private const val ENROLL_NOTIFICATION_ID = 3
        private const val DEFAULT_MTU = 20
        const val ACTION_SIGN_REQUEST = "com.example.pocketsshagent.ACTION_SIGN_REQUEST"
        const val ACTION_CANCEL_SIGN = "com.example.pocketsshagent.ACTION_CANCEL_SIGN"
        const val ACTION_ENROLL_REQUEST = "com.example.pocketsshagent.ACTION_ENROLL_REQUEST"
        const val ACTION_CANCEL_ENROLL = "com.example.pocketsshagent.ACTION_CANCEL_ENROLL"
        private const val SIGN_REQUEST_TIMEOUT_MS = 30_000L
        private const val ENROLL_REQUEST_TIMEOUT_MS = 60_000L
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

    private lateinit var bluetoothManager: BluetoothManager
    private var gattServer: BluetoothGattServer? = null
    private var advertiser: BluetoothLeAdvertiser? = null
    private lateinit var trustStore: TrustStore
    private lateinit var keyManager: KeyManager

    // Shared locks — only one signing or enroll dialog at a time across all devices.
    private val operationInProgress = AtomicBoolean(false)
    // Which device addr currently holds the signing lock (null when idle).
    @Volatile private var signingDeviceAddr: String? = null

    // Per-device state
    private val deviceAssemblers = mutableMapOf<String, BleFrameAssembler>()
    private val deviceMtu = mutableMapOf<String, Int>()
    private val deviceHandlers = mutableMapOf<String, SshAgentHandler>()
    private val subscribedDevices = mutableSetOf<BluetoothDevice>()

    private var txCharacteristic: BluetoothGattCharacteristic? = null
    private var isAdvertising = false

    // Binder for local binding (e.g., to set AgentCallback from Activity)
    private val binder = LocalBinder()
    @Volatile private var agentCallback: AgentCallback? = null
    @Volatile private var pendingSignRequest: PendingSignRequest? = null

    private val mainHandler = Handler(Looper.getMainLooper())
    private val signTimeoutRunnable = Runnable { cancelPendingSignRequest() }
    @Volatile private var pendingEnrollRequest: PendingEnrollRequest? = null
    private val enrollTimeoutRunnable = Runnable { cancelPendingEnrollRequest() }

    inner class LocalBinder : Binder() {
        fun getService(): BleAgentService = this@BleAgentService
    }

    override fun onBind(intent: Intent?): IBinder = binder

    fun setAgentCallback(callback: AgentCallback) {
        this.agentCallback = callback
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

    fun postEnrollNotification(label: String, deviceName: String?) {
        val tapIntent = Intent(this, MainActivity::class.java).apply {
            action = ACTION_ENROLL_REQUEST
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_NEW_TASK
        }
        val tapPi = PendingIntent.getActivity(
            this, 1, tapIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val cancelPi = PendingIntent.getService(
            this, 1,
            Intent(this, BleAgentService::class.java).apply { action = ACTION_CANCEL_ENROLL },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val contentText = if (deviceName != null) "$deviceName wants to create key: $label" else "Tap to review new SSH key: $label"
        val notification = Notification.Builder(this, ENROLL_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_sys_data_bluetooth)
            .setContentTitle("New SSH Key Request")
            .setContentText(contentText)
            .setContentIntent(tapPi)
            .setDeleteIntent(cancelPi)
            .setAutoCancel(true)
            .setPriority(Notification.PRIORITY_HIGH)
            .build()
        getSystemService(NotificationManager::class.java).notify(ENROLL_NOTIFICATION_ID, notification)
    }

    fun postSignNotification(keyLabel: String, deviceName: String?) {
        val tapIntent = Intent(this, MainActivity::class.java).apply {
            action = ACTION_SIGN_REQUEST
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_NEW_TASK
        }
        val tapPi = PendingIntent.getActivity(
            this, 0, tapIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val cancelPi = PendingIntent.getService(
            this, 0,
            Intent(this, BleAgentService::class.java).apply { action = ACTION_CANCEL_SIGN },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val contentText = if (deviceName != null) "$deviceName wants to sign with: $keyLabel" else "Tap to approve signing with: $keyLabel"
        val notification = Notification.Builder(this, SIGN_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_sys_data_bluetooth)
            .setContentTitle("SSH Sign Request")
            .setContentText(contentText)
            .setContentIntent(tapPi)
            .setDeleteIntent(cancelPi)
            .setAutoCancel(true)
            .setPriority(Notification.PRIORITY_HIGH)
            .build()
        getSystemService(NotificationManager::class.java).notify(SIGN_NOTIFICATION_ID, notification)
    }

    private val bluetoothStateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action != BluetoothAdapter.ACTION_STATE_CHANGED) return
            when (intent.getIntExtra(BluetoothAdapter.EXTRA_STATE, BluetoothAdapter.ERROR)) {
                BluetoothAdapter.STATE_ON -> {
                    Log.i(TAG, "Bluetooth enabled, restarting BLE stack")
                    restartBleStack()
                }
                BluetoothAdapter.STATE_OFF -> {
                    Log.i(TAG, "Bluetooth disabled, cleaning up BLE state")
                    cleanupBleState()
                }
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        bluetoothManager = getSystemService(BluetoothManager::class.java)
        trustStore = TrustStore(this)
        keyManager = KeyManager(this)
        registerReceiver(bluetoothStateReceiver, IntentFilter(BluetoothAdapter.ACTION_STATE_CHANGED))
        createNotificationChannel()
        startForeground(NOTIFICATION_ID, buildNotification())
    }

    private fun cleanupBleState() {
        // Explicitly stop advertising so Android doesn't auto-restore the session
        // when Bluetooth is re-enabled, which would cause ALREADY_STARTED on restart.
        if (hasBluetoothPermission()) {
            try { advertiser?.stopAdvertising(advertiseCallback) } catch (_: Exception) {}
        }
        advertiser = null
        gattServer?.close()
        gattServer = null
        isAdvertising = false
        subscribedDevices.clear()
        deviceAssemblers.clear()
        deviceMtu.clear()
        deviceHandlers.clear()
        cancelPendingSignRequest()
        cancelPendingEnrollRequest()
    }

    private fun restartBleStack() {
        cleanupBleState()
        startGattServer()
        startAdvertising()
    }

    private fun createAgentHandler(addr: String): SshAgentHandler {
        return SshAgentHandler(keyManager, object : AgentCallback {
            override fun requestBiometricSign(alias: String, keyLabel: String, deviceName: String?, data: ByteArray, onResult: (ByteArray?) -> Unit) {
                val cb = agentCallback
                if (cb != null) {
                    signingDeviceAddr = addr
                    cb.requestBiometricSign(alias, keyLabel, deviceName, data) { signature ->
                        if (signingDeviceAddr == addr) signingDeviceAddr = null
                        onResult(signature)
                    }
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
        }, trustStore, operationInProgress)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_CANCEL_SIGN) {
            cancelPendingSignRequest()
            return START_NOT_STICKY
        }
        if (intent?.action == ACTION_CANCEL_ENROLL) {
            cancelPendingEnrollRequest()
            return START_NOT_STICKY
        }
        startGattServer()
        startAdvertising()
        return START_STICKY
    }

    override fun onDestroy() {
        unregisterReceiver(bluetoothStateReceiver)
        mainHandler.removeCallbacks(signTimeoutRunnable)
        cleanupBleState()
        super.onDestroy()
    }

    // ─── GATT Server ────────────────────────────────────────────────────────────

    private fun startGattServer() {
        if (!hasBluetoothPermission()) {
            Log.e(TAG, "Missing Bluetooth permissions")
            return
        }
        if (gattServer != null) {
            Log.d(TAG, "GATT server already running, skipping")
            return
        }

        gattServer = bluetoothManager.openGattServer(this, gattCallback)
        val service = BluetoothGattService(
            BleUuids.SSH_AGENT_SERVICE,
            BluetoothGattService.SERVICE_TYPE_PRIMARY
        )

        // RX characteristic: client writes requests here
        val rxChar = BluetoothGattCharacteristic(
            BleUuids.AGENT_RX,
            BluetoothGattCharacteristic.PROPERTY_WRITE or
                    BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE,
            BluetoothGattCharacteristic.PERMISSION_WRITE
        )

        // TX characteristic: server notifies responses here
        val txChar = BluetoothGattCharacteristic(
            BleUuids.AGENT_TX,
            BluetoothGattCharacteristic.PROPERTY_NOTIFY,
            BluetoothGattCharacteristic.PERMISSION_READ
        )
        val cccd = BluetoothGattDescriptor(
            BleUuids.CCCD,
            BluetoothGattDescriptor.PERMISSION_WRITE or BluetoothGattDescriptor.PERMISSION_READ
        )
        txChar.addDescriptor(cccd)
        txCharacteristic = txChar

        service.addCharacteristic(rxChar)
        service.addCharacteristic(txChar)

        gattServer?.addService(service)
        Log.i(TAG, "GATT server started")
    }

    private val gattCallback = object : BluetoothGattServerCallback() {

        override fun onConnectionStateChange(device: BluetoothDevice, status: Int, newState: Int) {
            if (newState == BluetoothGatt.STATE_DISCONNECTED) {
                val addr = device.address
                deviceAssemblers.remove(addr)
                deviceMtu.remove(addr)
                deviceHandlers.remove(addr)
                subscribedDevices.remove(device)
                // If this device held the foreground signing lock, release it.
                if (signingDeviceAddr == addr) {
                    operationInProgress.set(false)
                    signingDeviceAddr = null
                }
                cancelPendingSignRequest()
                Log.i(TAG, "Device disconnected: $addr")
            } else if (newState == BluetoothGatt.STATE_CONNECTED) {
                // Don't reset session on connect - STATE_CONNECTED can fire multiple
                // times during connection (e.g., after MTU negotiation), which would
                // clear authentication. Session is reset on disconnect or explicit auth.
                Log.i(TAG, "Device connected: ${device.address}")
            }
        }

        override fun onMtuChanged(device: BluetoothDevice, mtu: Int) {
            // Effective payload = MTU - 3 (ATT header)
            deviceMtu[device.address] = mtu - 3
            Log.d(TAG, "MTU changed for ${device.address}: $mtu (payload: ${mtu - 3})")
        }

        override fun onCharacteristicWriteRequest(
            device: BluetoothDevice,
            requestId: Int,
            characteristic: BluetoothGattCharacteristic,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray?
        ) {
            if (characteristic.uuid == BleUuids.AGENT_RX && value != null) {
                handleIncomingChunk(device, value)
                if (responseNeeded) {
                    gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, null)
                }
            } else {
                if (responseNeeded) {
                    gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, 0, null)
                }
            }
        }

        override fun onDescriptorWriteRequest(
            device: BluetoothDevice,
            requestId: Int,
            descriptor: BluetoothGattDescriptor,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray?
        ) {
            if (descriptor.uuid == BleUuids.CCCD) {
                if (value.contentEquals(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE)) {
                    subscribedDevices.add(device)
                    Log.d(TAG, "Device subscribed to TX: ${device.address}")
                } else {
                    subscribedDevices.remove(device)
                    Log.d(TAG, "Device unsubscribed from TX: ${device.address}")
                }
                if (responseNeeded) {
                    gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, null)
                }
            }
        }
    }

    private fun handleIncomingChunk(device: BluetoothDevice, chunk: ByteArray) {
        val addr = device.address
        val assembler = deviceAssemblers.getOrPut(addr) { BleFrameAssembler() }
        // frame = [4B corr_id][ssh_msg]
        val frame = assembler.feed(chunk) ?: return

        Log.d(TAG, "Complete agent message received from $addr (${frame.size} bytes)")

        if (frame.size < 4) {
            Log.w(TAG, "Frame too short for correlation ID from $addr")
            return
        }

        // Extract correlation ID so we can echo it back in the response, letting
        // multiple independent clients sharing the same BLE connection filter
        // responses that belong to them.
        val correlationId = frame.copyOfRange(0, 4)
        val message = frame.copyOfRange(4, frame.size)

        val handler = deviceHandlers.getOrPut(addr) { createAgentHandler(addr) }
        handler.handleMessage(message) { response ->
            // response = SshWireFormat.frameMessage(result) = [4B ssh_len][result]
            // Send: [4B ble_len][4B corr_id][4B ssh_len][result]
            val blePayload = correlationId + response
            val bleFrame = SshWireFormat.encodeUint32(blePayload.size) + blePayload
            Log.d(TAG, "Sending response to $addr (${bleFrame.size} bytes)")
            sendResponse(device, bleFrame)
        }
    }

    private fun sendResponse(device: BluetoothDevice, framedResponse: ByteArray) {
        val tx = txCharacteristic ?: return
        val server = gattServer ?: return
        val mtu = deviceMtu[device.address] ?: DEFAULT_MTU

        Log.d(TAG, "sendResponse: ${framedResponse.size} bytes, MTU=$mtu, subscribed=${subscribedDevices.contains(device)}")

        val chunks = BleFrameChunker.chunk(framedResponse, mtu)
        for ((i, chunk) in chunks.withIndex()) {
            tx.value = chunk
            val result = server.notifyCharacteristicChanged(device, tx, false)
            Log.d(TAG, "Sent chunk $i/${chunks.size}: ${chunk.size} bytes, result=$result")
        }
    }

    // ─── BLE Advertising ────────────────────────────────────────────────────────

    private fun startAdvertising() {
        if (!hasBluetoothPermission()) return
        if (isAdvertising) {
            Log.d(TAG, "Advertising already started, skipping")
            return
        }

        val adapter = bluetoothManager.adapter ?: return
        advertiser = adapter.bluetoothLeAdvertiser

        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setConnectable(true)
            .setTimeout(0) // Advertise indefinitely
            .build()

        val data = AdvertiseData.Builder()
            .setIncludeDeviceName(true)
            .addServiceUuid(ParcelUuid(BleUuids.SSH_AGENT_SERVICE))
            .build()

        advertiser?.startAdvertising(settings, data, advertiseCallback)
        Log.i(TAG, "BLE advertising started")
    }

    private fun stopAdvertising() {
        if (!hasBluetoothPermission()) return
        advertiser?.stopAdvertising(advertiseCallback)
        isAdvertising = false
        Log.i(TAG, "BLE advertising stopped")
    }

    private val advertiseCallback = object : AdvertiseCallback() {
        override fun onStartSuccess(settingsInEffect: AdvertiseSettings?) {
            isAdvertising = true
            Log.i(TAG, "Advertising started successfully")
        }

        override fun onStartFailure(errorCode: Int) {
            if (errorCode == ADVERTISE_FAILED_ALREADY_STARTED) {
                // Android auto-restored a previous advertising session; treat as success.
                isAdvertising = true
                Log.i(TAG, "Advertising already active (restored by system)")
            } else {
                isAdvertising = false
                Log.e(TAG, "Advertising failed with error code: $errorCode")
            }
        }
    }

    // ─── Notification ───────────────────────────────────────────────────────────

    private fun createNotificationChannel() {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel(
                NOTIFICATION_CHANNEL_ID,
                "SSH Agent",
                NotificationManager.IMPORTANCE_LOW
            ).apply { description = "SSH Agent BLE service is active" }
        )
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

    private fun buildNotification(): Notification {
        return Notification.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setContentTitle("SSH Agent Active")
            .setContentText("Listening for BLE connections")
            .setSmallIcon(android.R.drawable.stat_sys_data_bluetooth)
            .setOngoing(true)
            .build()
    }

    // ─── Permissions ────────────────────────────────────────────────────────────

    private fun hasBluetoothPermission(): Boolean {
        return checkSelfPermission(android.Manifest.permission.BLUETOOTH_ADVERTISE) ==
                PackageManager.PERMISSION_GRANTED &&
                checkSelfPermission(android.Manifest.permission.BLUETOOTH_CONNECT) ==
                PackageManager.PERMISSION_GRANTED
    }
}
