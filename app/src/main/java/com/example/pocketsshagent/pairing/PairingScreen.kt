package com.example.pocketsshagent.pairing

import android.Manifest
import android.content.pm.PackageManager
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun PairingScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val trustStore = remember { TrustStore(context) }
    var devices by remember { mutableStateOf(trustStore.getAllDevices()) }
    var scanning by remember { mutableStateOf(false) }
    var hasCameraPermission by remember {
        mutableStateOf(
            context.checkSelfPermission(Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED
        )
    }

    val cameraPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        hasCameraPermission = granted
        if (granted) {
            scanning = true
        } else {
            Toast.makeText(context, "Camera permission required for QR scanning", Toast.LENGTH_SHORT).show()
        }
    }

    if (scanning) {
        Column(modifier = Modifier.fillMaxSize()) {
            Box(modifier = Modifier.weight(1f)) {
                QrScannerView(
                    onQrScanned = { qrContent ->
                        val device = PairingProtocol.completePairing(qrContent, trustStore)
                        if (device != null) {
                            Toast.makeText(context, "Paired with: ${device.label}", Toast.LENGTH_SHORT).show()
                            devices = trustStore.getAllDevices()
                        } else {
                            Toast.makeText(context, "Pairing failed — invalid QR code", Toast.LENGTH_SHORT).show()
                        }
                        scanning = false
                    }
                )
            }
            Button(
                onClick = { scanning = false },
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp)
            ) {
                Text("Cancel")
            }
        }
        return
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = "Paired Devices",
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.SemiBold
            )
            TextButton(onClick = onBack) {
                Text("Back")
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

        Button(
            onClick = {
                if (hasCameraPermission) {
                    scanning = true
                } else {
                    cameraPermissionLauncher.launch(Manifest.permission.CAMERA)
                }
            },
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("Scan QR to Pair Device")
        }

        Spacer(modifier = Modifier.height(16.dp))

        if (devices.isEmpty()) {
            Text("No paired devices. Scan a QR code from the desktop proxy to pair.")
        } else {
            LazyColumn(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                items(devices) { device ->
                    DeviceRow(
                        device = device,
                        onRemove = {
                            trustStore.removeDevice(device.publicKey)
                            devices = trustStore.getAllDevices()
                            Toast.makeText(context, "Removed: ${device.label}", Toast.LENGTH_SHORT).show()
                        }
                    )
                    HorizontalDivider()
                }
            }
        }
    }
}

@Composable
private fun DeviceRow(device: TrustedDevice, onRemove: () -> Unit) {
    val dateFormat = remember { SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault()) }

    Column(modifier = Modifier.fillMaxWidth()) {
        Text(text = device.label, style = MaterialTheme.typography.titleMedium)
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = "Paired: ${dateFormat.format(Date(device.pairedAtEpochMs))}",
            style = MaterialTheme.typography.bodySmall
        )
        if (device.lastSeenAtEpochMs > 0) {
            Text(
                text = "Last seen: ${dateFormat.format(Date(device.lastSeenAtEpochMs))}",
                style = MaterialTheme.typography.bodySmall
            )
        }
        Spacer(modifier = Modifier.height(4.dp))
        TextButton(onClick = onRemove) {
            Text("Remove")
        }
    }
}
