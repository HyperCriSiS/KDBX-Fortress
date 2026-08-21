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

            val kdbx = assets.open(FIXTURE_NAME).use { it.readBytes() }
            val password = FIXTURE_PASSWORD.toByteArray(Charsets.UTF_8)
            try {
                NativeBridge.verifyVaultLifecycle(kdbx, password)
            } finally {
                password.fill(0)
                kdbx.fill(0)
            }

            "PASS"
        } catch (error: Throwable) {
            "FAIL:${error.javaClass.simpleName}"
        }

        File(filesDir, RESULT_FILE).writeText(result, Charsets.US_ASCII)
        finishAndRemoveTask()
    }

    private companion object {
        const val RESULT_FILE = "jni-smoke-result"
        const val FIXTURE_NAME = "basic-kdbx4.kdbx"
        const val FIXTURE_PASSWORD = "fixture-password"
    }
}
