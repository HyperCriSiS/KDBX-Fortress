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
            NativeBridge.verifyMalformedHandleBoundary()

            val kdbx = assets.open(FIXTURE_NAME).use { it.readBytes() }
            val password = FIXTURE_PASSWORD.toByteArray(Charsets.UTF_8)
            try {
                // Two real decrypted vaults remain Rust-owned and live until CI
                // deliberately backgrounds this Activity. KDF work can take
                // longer than Android's `am start -W` launch timeout, so READY
                // is an explicit synchronization point for the external harness.
                lifecycleHandles = NativeBridge.openLifecycleProbeVaults(kdbx, password)
                lifecycleArmed = true
                File(filesDir, READY_FILE).writeText("READY", Charsets.US_ASCII)
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
        const val READY_FILE = "jni-smoke-ready"
        const val RESULT_FILE = "jni-smoke-result"
        const val FIXTURE_NAME = "basic-kdbx4.kdbx"
        const val FIXTURE_PASSWORD = "fixture-password"
    }
}
