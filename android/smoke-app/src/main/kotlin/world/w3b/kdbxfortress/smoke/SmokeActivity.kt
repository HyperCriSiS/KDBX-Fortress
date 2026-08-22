package world.w3b.kdbxfortress.smoke

import android.app.Activity
import android.os.Bundle
import java.io.File
import world.w3b.kdbxfortress.bridge.NativeBridge

class SmokeActivity : Activity() {
    private var lifecycleHandles = LongArray(0)
    private var lifecycleArmed = false
    private var resultWritten = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        try {
            NativeBridge.verifyRuntimeBoundary()

            val kdbx = assets.open(FIXTURE_NAME).use { it.readBytes() }
            val password = FIXTURE_PASSWORD.toByteArray(Charsets.UTF_8)
            try {
                NativeBridge.verifyInvalidAndStaleHandleBehavior(kdbx, password)
                lifecycleHandles = NativeBridge.openLifecycleProbeVaults(kdbx, password)
                lifecycleArmed = true
            } finally {
                password.fill(0)
                kdbx.fill(0)
            }
        } catch (error: Throwable) {
            runCatching { NativeBridge.lockAllForFailureCleanup() }
            writeResult("FAIL:${error.javaClass.simpleName}")
            finishAndRemoveTask()
        }
    }

    override fun onStop() {
        super.onStop()
        if (!lifecycleArmed || resultWritten) {
            return
        }

        val result = try {
            NativeBridge.verifyLifecycleLockAll(lifecycleHandles)
            "PASS"
        } catch (error: Throwable) {
            "FAIL:${error.javaClass.simpleName}"
        } finally {
            lifecycleHandles.fill(0L)
            lifecycleHandles = LongArray(0)
            lifecycleArmed = false
        }

        writeResult(result)
        finishAndRemoveTask()
    }

    private fun writeResult(result: String) {
        if (resultWritten) {
            return
        }
        resultWritten = true
        File(filesDir, RESULT_FILE).writeText(result, Charsets.US_ASCII)
    }

    private companion object {
        const val RESULT_FILE = "jni-smoke-result"
        const val FIXTURE_NAME = "basic-kdbx4.kdbx"
        const val FIXTURE_PASSWORD = "fixture-password"
    }
}
