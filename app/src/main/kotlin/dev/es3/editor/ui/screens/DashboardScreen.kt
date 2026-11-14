package dev.es3.editor.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp
import dev.es3.core.common.AppInfo
import dev.es3.editor.ui.Dest
import dev.es3.legacy.easysave3.LegacyStatus

@Composable
fun DashboardScreen(onOpen: (Dest) -> Unit) {
    Scaffold { pad ->
        LazyColumn(
            Modifier.fillMaxSize().padding(pad).padding(horizontal = 20.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            item {
                Spacer(Modifier.height(16.dp))
                Text("ES.3", style = MaterialTheme.typography.displaySmall, color = MaterialTheme.colorScheme.primary)
                Text("Save encryption, compression & inspection", color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            item {
                val actions = listOf(
                    Triple(Dest.Encrypt, Icons.Filled.Lock, "Encrypt"),
                    Triple(Dest.Decrypt, Icons.Filled.LockOpen, "Decrypt"),
                    Triple(Dest.Compress, Icons.Filled.Compress, "Compress"),
                    Triple(Dest.Editor, Icons.Filled.Edit, "Save Editor")
                )
                LazyVerticalGrid(
                    GridCells.Fixed(2), Modifier.height(260.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                    userScrollEnabled = false
                ) {
                    items(actions.size) { i -> ActionCard(actions[i].third, actions[i].second) { onOpen(actions[i].first) } }
                }
            }
            item { InfoCard("Recent files", "No files yet.") }
            item { InfoCard("Recent operations", "No operations yet.") }
            item { InfoCard("Application status", "${AppInfo.NAME} ${AppInfo.VERSION}\nStage 1 — foundation only. No cryptography implemented yet.") }
            item { InfoCard("Legacy compatibility", LegacyStatus.current.label) }
            item { Spacer(Modifier.height(24.dp)) }
        }
    }
}

@Composable
private fun ActionCard(label: String, icon: ImageVector, onClick: () -> Unit) {
    Card(
        Modifier.fillMaxWidth().height(124.dp).clickable(onClick = onClick),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerHigh)
    ) {
        Column(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.SpaceBetween) {
            Icon(icon, null, tint = MaterialTheme.colorScheme.primary)
            Text(label, style = MaterialTheme.typography.titleMedium)
        }
    }
}

@Composable
private fun InfoCard(title: String, body: String) {
    Card(Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)) {
        Column(Modifier.padding(16.dp)) {
            Text(title, style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary)
            Spacer(Modifier.height(4.dp))
            Text(body, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}
