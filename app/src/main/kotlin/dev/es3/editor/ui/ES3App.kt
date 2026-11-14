package dev.es3.editor.ui

import androidx.compose.runtime.Composable
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import dev.es3.editor.ui.screens.DashboardScreen
import dev.es3.editor.ui.screens.NotImplementedScreen

enum class Dest(val route: String, val title: String, val stage: Int) {
    Encrypt("encrypt", "Encrypt", 2),
    Decrypt("decrypt", "Decrypt", 3),
    Compress("compress", "Compression", 4),
    Editor("editor", "Save Editor", 5),
    History("history", "File History", 7),
    Settings("settings", "Settings", 7),
    About("about", "About ES.3", 7)
}

@Composable
fun ES3App() {
    val nav = rememberNavController()
    NavHost(nav, startDestination = "dashboard") {
        composable("dashboard") { DashboardScreen(onOpen = { nav.navigate(it.route) }) }
        Dest.entries.forEach { d ->
            composable(d.route) { NotImplementedScreen(d, onBack = { nav.popBackStack() }) }
        }
    }
}
