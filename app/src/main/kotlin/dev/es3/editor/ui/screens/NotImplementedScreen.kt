package dev.es3.editor.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import dev.es3.editor.ui.Dest

/** Honest placeholder: no fake controls. Replaced stage by stage. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NotImplementedScreen(dest: Dest, onBack: () -> Unit) {
    Scaffold(topBar = {
        TopAppBar(title = { Text(dest.title) }, navigationIcon = {
            IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back") }
        })
    }) { pad ->
        Box(Modifier.fillMaxSize().padding(pad).padding(24.dp), contentAlignment = Alignment.Center) {
            Text("Not implemented yet — planned for Stage ${dest.stage}.",
                color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}
