package world.w3b.kdbxfortress

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import world.w3b.kdbxfortress.bridge.NativeBridge
import world.w3b.kdbxfortress.ui.KdbxFortressApp
import world.w3b.kdbxfortress.ui.theme.KdbxFortressTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        val nativeReady = runCatching {
            NativeBridge.verifyRuntimeBoundary()
        }.isSuccess

        setContent {
            KdbxFortressTheme {
                KdbxFortressApp(nativeReady = nativeReady)
            }
        }
    }

    override fun onStop() {
        runCatching { NativeBridge.lockAllVaults() }
        super.onStop()
    }
}
