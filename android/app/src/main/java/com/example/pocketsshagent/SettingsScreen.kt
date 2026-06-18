package com.example.pocketsshagent

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
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
import com.example.pocketsshagent.data.SettingsStore

@Composable
fun SettingsScreen(
    onBack: () -> Unit = {},
    onBleToggled: (Boolean) -> Unit = {},
    onTermuxToggled: (Boolean) -> Unit = {}
) {
    val context = LocalContext.current.applicationContext
    val settingsStore = remember { SettingsStore(context) }
    var bleEnabled by remember { mutableStateOf(settingsStore.bleEnabled) }
    var termuxEnabled by remember { mutableStateOf(settingsStore.termuxEnabled) }

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
                text = "Settings",
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.SemiBold
            )
            TextButton(onClick = onBack) {
                Text("Back")
            }
        }
        Spacer(modifier = Modifier.height(16.dp))

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(text = "BLE Service", style = MaterialTheme.typography.titleMedium)
                Text(
                    text = "Allow desktop connections over Bluetooth",
                    style = MaterialTheme.typography.bodySmall
                )
            }
            Switch(
                checked = bleEnabled,
                onCheckedChange = {
                    bleEnabled = it
                    settingsStore.bleEnabled = it
                    onBleToggled(it)
                }
            )
        }
        Spacer(modifier = Modifier.height(8.dp))
        HorizontalDivider()
        Spacer(modifier = Modifier.height(8.dp))

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(text = "Termux Service", style = MaterialTheme.typography.titleMedium)
                Text(
                    text = "Allow Termux to use SSH keys on this device",
                    style = MaterialTheme.typography.bodySmall
                )
            }
            Switch(
                checked = termuxEnabled,
                onCheckedChange = {
                    termuxEnabled = it
                    settingsStore.termuxEnabled = it
                    onTermuxToggled(it)
                }
            )
        }
    }
}
