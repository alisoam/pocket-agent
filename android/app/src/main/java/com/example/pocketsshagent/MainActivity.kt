package com.example.pocketsshagent

import android.Manifest
import android.content.ClipData
import android.content.ClipboardManager
import android.content.ComponentName
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.os.Bundle
import android.os.IBinder
import android.widget.Toast
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TextField
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import com.example.pocketsshagent.agent.SshPublicKeyUtils
import com.example.pocketsshagent.ble.BleAgentService
import com.example.pocketsshagent.crypto.BiometricAgentCallback
import com.example.pocketsshagent.data.SettingsStore
import com.example.pocketsshagent.crypto.KeyManager
import com.example.pocketsshagent.model.KeyMetadata
import com.example.pocketsshagent.pairing.PairingScreen
import com.example.pocketsshagent.termux.AgentContentProvider
import com.example.pocketsshagent.termux.TermuxAgentService
import com.example.pocketsshagent.termux.TermuxBiometricCallback
import com.example.pocketsshagent.ui.theme.PocketSSHAgentTheme

class MainActivity : FragmentActivity() {

    private var bleService: BleAgentService? = null
    private var biometricCallback: BiometricAgentCallback? = null
    private var termuxService: TermuxAgentService? = null
    private var termuxBiometricCallback: TermuxBiometricCallback? = null

    private val serviceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
            val binder = service as BleAgentService.LocalBinder
            val svc = binder.getService()
            bleService = svc
            val cb = BiometricAgentCallback(this@MainActivity, svc)
            biometricCallback = cb
            svc.setAgentCallback(cb)
            cb.resumePendingSign()
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            bleService = null
            biometricCallback = null
        }
    }

    private val termuxServiceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
            val binder = service as TermuxAgentService.LocalBinder
            val svc = binder.getService()
            termuxService = svc
            val cb = TermuxBiometricCallback(this@MainActivity, svc)
            termuxBiometricCallback = cb
            svc.setAgentCallback(cb)
            AgentContentProvider.agentCallback = cb
            cb.resumePendingSign()
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            termuxService = null
            termuxBiometricCallback = null
        }
    }

    private val requiredPermissions = arrayOf(
        Manifest.permission.BLUETOOTH_ADVERTISE,
        Manifest.permission.BLUETOOTH_CONNECT,
        Manifest.permission.POST_NOTIFICATIONS
    )

    private val permissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { results ->
        val allGranted = results.values.all { it }
        if (allGranted) {
            startServices()
        } else {
            Toast.makeText(this, "Bluetooth permissions required for SSH agent", Toast.LENGTH_LONG).show()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        // Request permissions then start service
        if (hasRequiredPermissions()) {
            startServices()
        } else {
            permissionLauncher.launch(requiredPermissions)
        }

        setContent {
            val settingsStore = remember { SettingsStore(this) }
            var themeMode by remember { mutableStateOf(settingsStore.themeMode) }
            val darkTheme = when (themeMode) {
                SettingsStore.THEME_DARK -> true
                SettingsStore.THEME_LIGHT -> false
                else -> isSystemInDarkTheme()
            }
            PocketSSHAgentTheme(darkTheme = darkTheme) {
                var currentScreen by remember { mutableStateOf("keys") }
                when (currentScreen) {
                    "keys" -> KeyListScreen(
                        onNavigateToPairing = { currentScreen = "pairing" },
                        onNavigateToSettings = { currentScreen = "settings" }
                    )
                    "pairing" -> PairingScreen(onBack = { currentScreen = "keys" })
                    "settings" -> SettingsScreen(
                        onBack = { currentScreen = "keys" },
                        onBleToggled = { enabled -> toggleBleService(enabled) },
                        onTermuxToggled = { enabled -> toggleTermuxService(enabled) },
                        onThemeChanged = { mode -> themeMode = mode }
                    )
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        biometricCallback?.resumePendingSign()
        biometricCallback?.resumePendingEnroll()
        termuxBiometricCallback?.resumePendingSign()
        termuxBiometricCallback?.resumePendingEnroll()
        termuxBiometricCallback?.resumePendingResidentAccess()
    }

    override fun onDestroy() {
        if (bleService != null) {
            unbindService(serviceConnection)
        }
        if (termuxService != null) {
            unbindService(termuxServiceConnection)
        }
        super.onDestroy()
    }

    private fun startServices() {
        val settings = SettingsStore(this)
        if (settings.bleEnabled) {
            val serviceIntent = Intent(this, BleAgentService::class.java)
            startForegroundService(serviceIntent)
            bindService(serviceIntent, serviceConnection, BIND_AUTO_CREATE)
        }
        if (settings.termuxEnabled) {
            bindService(Intent(this, TermuxAgentService::class.java), termuxServiceConnection, BIND_AUTO_CREATE)
        }
    }

    private fun toggleBleService(enabled: Boolean) {
        if (enabled) {
            val serviceIntent = Intent(this, BleAgentService::class.java)
            startForegroundService(serviceIntent)
            bindService(serviceIntent, serviceConnection, BIND_AUTO_CREATE)
        } else {
            if (bleService != null) {
                unbindService(serviceConnection)
                bleService = null
                biometricCallback = null
            }
            stopService(Intent(this, BleAgentService::class.java))
        }
    }

    private fun toggleTermuxService(enabled: Boolean) {
        if (enabled) {
            bindService(Intent(this, TermuxAgentService::class.java), termuxServiceConnection, BIND_AUTO_CREATE)
        } else {
            if (termuxService != null) {
                unbindService(termuxServiceConnection)
                termuxService = null
                termuxBiometricCallback = null
            }
        }
    }

    private fun hasRequiredPermissions(): Boolean {
        return requiredPermissions.all {
            checkSelfPermission(it) == PackageManager.PERMISSION_GRANTED
        }
    }
}

@Composable
fun KeyListScreen(onNavigateToPairing: () -> Unit = {}, onNavigateToSettings: () -> Unit = {}) {
    val context = LocalContext.current.applicationContext
    val keyManager = remember { KeyManager(context) }
    var keys by remember { mutableStateOf(emptyList<KeyMetadata>()) }
    var showDialog by remember { mutableStateOf(false) }
    var labelInput by remember { mutableStateOf("") }
    var selectedAlg by remember { mutableStateOf("ed25519") }
    var isResident by remember { mutableStateOf(false) }

    val keysVersion by KeyManager.keysVersion.collectAsState()
    LaunchedEffect(keysVersion) {
        keys = keyManager.listKeys()
    }

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        floatingActionButton = {
            FloatingActionButton(onClick = { showDialog = true }) {
                Text(text = "+")
            }
        }
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .padding(16.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = androidx.compose.ui.Alignment.CenterVertically
            ) {
                Text(
                    text = "SSH Keys",
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.SemiBold
                )
                Row {
                    TextButton(onClick = onNavigateToSettings) {
                        Text("Settings")
                    }
                    TextButton(onClick = onNavigateToPairing) {
                        Text("Devices")
                    }
                }
            }
            Spacer(modifier = Modifier.height(12.dp))
            if (keys.isEmpty()) {
                Text(text = "No keys yet. Create one to get started.")
            } else {
                LazyColumn(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    items(keys) { key ->
                        KeyRow(
                            key = key,
                            keyManager = keyManager,
                            onDelete = {
                                keyManager.deleteKey(key.alias)
                                keys = keyManager.listKeys()
                            },
                            onRenamed = { keys = keyManager.listKeys() }
                        )
                        HorizontalDivider()
                    }
                }
            }
        }
    }

    if (showDialog) {
        val algorithms = listOf("ed25519", "ecdsa")
        AlertDialog(
            onDismissRequest = { showDialog = false },
            confirmButton = {
                Button(
                    onClick = {
                        val label = labelInput.trim()
                        if (label.isNotEmpty()) {
                            keyManager.generateKey(label, isEcdsa = selectedAlg == "ecdsa", resident = isResident)
                            keys = keyManager.listKeys()
                            labelInput = ""
                            selectedAlg = "ed25519"
                            isResident = false
                            showDialog = false
                        }
                    }
                ) {
                    Text(text = "Create")
                }
            },
            dismissButton = {
                TextButton(onClick = { showDialog = false }) {
                    Text(text = "Cancel")
                }
            },
            title = { Text(text = "Create SSH key") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text(text = "Choose a label. It cannot be changed later.")
                    TextField(
                        value = labelInput,
                        onValueChange = { labelInput = it },
                        singleLine = true,
                        placeholder = { Text(text = "e.g. Laptop") }
                    )
                    SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
                        algorithms.forEachIndexed { index, alg ->
                            SegmentedButton(
                                selected = selectedAlg == alg,
                                onClick = { selectedAlg = alg },
                                shape = SegmentedButtonDefaults.itemShape(index, algorithms.size)
                            ) {
                                Text(text = alg)
                            }
                        }
                    }
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(text = "Resident key")
                        Switch(checked = isResident, onCheckedChange = { isResident = it })
                    }
                }
            }
        )
    }
}

@Composable
private fun KeyRow(key: KeyMetadata, keyManager: KeyManager, onDelete: () -> Unit, onRenamed: () -> Unit = {}) {
    val context = LocalContext.current
    var showPublicKey by remember { mutableStateOf(false) }
    var publicKeyLine by remember { mutableStateOf("") }
    var fingerprint by remember { mutableStateOf("") }
    var showHandle by remember { mutableStateOf(false) }
    var keyFileContent by remember { mutableStateOf("") }
    var showRenameDialog by remember { mutableStateOf(false) }
    var renameInput by remember { mutableStateOf("") }

    Column(modifier = Modifier.fillMaxWidth()) {
        val keyType = remember(key.alias) {
            when (keyManager.getKeyAlgorithm(key.alias)) {
                "EC"               -> "ecdsa-sk"
                "Ed25519", "EdDSA" -> "ed25519-sk"
                else               -> "Unknown"
            }
        }
        Text(text = key.label, style = MaterialTheme.typography.titleMedium)
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = "$keyType · ${if (key.hardwareBacked) "Hardware-backed" else "Software-backed"} · ${if (key.resident) "Resident" else "Non-Resident"}",
            style = MaterialTheme.typography.bodySmall
        )
        Spacer(modifier = Modifier.height(8.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            TextButton(onClick = {
                try {
                    val pubKey = keyManager.getPublicKey(key.alias)
                    publicKeyLine = SshPublicKeyUtils.formatAuthorizedKeysLine(pubKey, key.label)
                    fingerprint = SshPublicKeyUtils.fingerprint(pubKey)
                    showPublicKey = true
                    showHandle = false
                } catch (e: Exception) {
                    android.util.Log.e("KeyRow", "Failed to read public key", e)
                    Toast.makeText(context, "Failed to read public key: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }) {
                Text(text = "Public Key")
            }
            TextButton(onClick = {
                if (!showHandle) {
                    try {
                        val pubKey = keyManager.getPublicKey(key.alias)
                        keyFileContent = SshPublicKeyUtils.formatOpenSshPrivateKeyFile(pubKey, key.alias, key.label)
                        showHandle = true
                        showPublicKey = false
                    } catch (e: Exception) {
                        android.util.Log.e("KeyRow", "Failed to build key file", e)
                        Toast.makeText(context, "Failed to build key file: ${e.message}", Toast.LENGTH_LONG).show()
                    }
                } else {
                    showHandle = false
                }
            }) {
                Text(text = "Handle")
            }
            TextButton(onClick = {
                renameInput = key.label
                showRenameDialog = true
            }) {
                Text(text = "Rename")
            }
            TextButton(onClick = onDelete) {
                Text(text = "Delete")
            }
        }

        if (showRenameDialog) {
            AlertDialog(
                onDismissRequest = { showRenameDialog = false },
                confirmButton = {
                    Button(
                        onClick = {
                            val newLabel = renameInput.trim()
                            if (newLabel.isNotEmpty()) {
                                keyManager.renameKey(key.alias, newLabel)
                                showRenameDialog = false
                                onRenamed()
                            }
                        }
                    ) { Text(text = "Rename") }
                },
                dismissButton = {
                    TextButton(onClick = { showRenameDialog = false }) { Text(text = "Cancel") }
                },
                title = { Text(text = "Rename key") },
                text = {
                    TextField(
                        value = renameInput,
                        onValueChange = { renameInput = it },
                        singleLine = true
                    )
                }
            )
        }

        if (showPublicKey) {
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = fingerprint,
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = publicKeyLine,
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                maxLines = 3,
                overflow = TextOverflow.Ellipsis
            )
            Spacer(modifier = Modifier.height(4.dp))
            TextButton(onClick = {
                val clipboard = context.getSystemService(ClipboardManager::class.java)
                clipboard.setPrimaryClip(ClipData.newPlainText("SSH Public Key", publicKeyLine))
                Toast.makeText(context, "Public key copied", Toast.LENGTH_SHORT).show()
            }) {
                Text(text = "Copy to Clipboard")
            }
        }

        if (showHandle) {
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = keyFileContent,
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace
            )
            TextButton(onClick = {
                val clipboard = context.getSystemService(ClipboardManager::class.java)
                clipboard.setPrimaryClip(ClipData.newPlainText("SSH SK Private Key File", keyFileContent))
                Toast.makeText(context, "Key file copied", Toast.LENGTH_SHORT).show()
            }) {
                Text(text = "Copy to Clipboard")
            }
        }
    }
}

@Preview(showBackground = true)
@Composable
fun GreetingPreview() {
    PocketSSHAgentTheme {
        KeyListScreen()
    }
}
