package world.w3b.kdbxfortress.smoke

import android.app.Activity
import android.os.Bundle
import java.io.File
import world.w3b.kdbxfortress.bridge.NativeBridge

class SmokeActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val result = try {
            NativeBridge.verifyRuntimeBoundary()
            "PASS"
        } catch (error: Throwable) {
            "FAIL:${error.javaClass.simpleName}"
        }

        File(filesDir, RESULT_FILE).writeText(result, Charsets.US_ASCII)
        finishAndRemoveTask()
    }

    private companion object {
        const val RESULT_FILE = "jni-smoke-result"
    }
}
