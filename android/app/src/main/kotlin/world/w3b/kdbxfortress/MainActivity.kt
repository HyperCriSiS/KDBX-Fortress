package world.w3b.kdbxfortress

import android.app.Activity
import android.os.Bundle
import android.view.Gravity
import android.widget.TextView
import world.w3b.kdbxfortress.bridge.NativeBridge

class MainActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val nativeReady = runCatching {
            NativeBridge.verifyRuntimeBoundary()
        }.isSuccess

        setContentView(
            TextView(this).apply {
                gravity = Gravity.CENTER
                textSize = 20f
                text = if (nativeReady) {
                    "KDBX Fortress\nNative vault core ready"
                } else {
                    "KDBX Fortress\nNative vault core unavailable"
                }
            },
        )
    }

    override fun onStop() {
        runCatching { NativeBridge.lockAllVaults() }
        super.onStop()
    }
}
