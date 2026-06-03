package com.example.pocketsshagent

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
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
import androidx.compose.material3.Divider
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TextField
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.example.pocketsshagent.crypto.KeyManager
import com.example.pocketsshagent.model.KeyMetadata
import com.example.pocketsshagent.ui.theme.PocketSSHAgentTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            PocketSSHAgentTheme {
                KeyListScreen()
            }
        }
    }
}

@Composable
fun KeyListScreen() {
    val context = LocalContext.current.applicationContext
    val keyManager = remember { KeyManager(context) }
    var keys by remember { mutableStateOf(emptyList<KeyMetadata>()) }
    var showDialog by remember { mutableStateOf(false) }
    var labelInput by remember { mutableStateOf("") }

    LaunchedEffect(Unit) {
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
            Text(
                text = "SSH Keys",
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.SemiBold
            )
            Spacer(modifier = Modifier.height(12.dp))
            if (keys.isEmpty()) {
                Text(text = "No keys yet. Create one to get started.")
            } else {
                LazyColumn(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    items(keys) { key ->
                        KeyRow(key = key, onDelete = {
                            keyManager.deleteKey(key.alias)
                            keys = keyManager.listKeys()
                        })
                        Divider()
                    }
                }
            }
        }
    }

    if (showDialog) {
        AlertDialog(
            onDismissRequest = { showDialog = false },
            confirmButton = {
                Button(
                    onClick = {
                        val label = labelInput.trim()
                        if (label.isNotEmpty()) {
                            keyManager.generateKey(label)
                            keys = keyManager.listKeys()
                            labelInput = ""
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
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(text = "Choose a label. It cannot be changed later.")
                    TextField(
                        value = labelInput,
                        onValueChange = { labelInput = it },
                        singleLine = true,
                        placeholder = { Text(text = "e.g. Laptop") }
                    )
                }
            }
        )
    }
}

@Composable
private fun KeyRow(key: KeyMetadata, onDelete: () -> Unit) {
    Column(modifier = Modifier.fillMaxWidth()) {
        Text(text = key.label, style = MaterialTheme.typography.titleMedium)
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = "Alias: ${key.alias}",
            style = MaterialTheme.typography.bodySmall
        )
        Text(
            text = if (key.hardwareBacked) "Hardware-backed" else "Software-backed",
            style = MaterialTheme.typography.bodySmall
        )
        Spacer(modifier = Modifier.height(8.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            TextButton(onClick = onDelete) {
                Text(text = "Delete")
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
