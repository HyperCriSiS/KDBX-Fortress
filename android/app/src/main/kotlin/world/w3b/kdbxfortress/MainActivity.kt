package world.w3b.kdbxfortress

import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import world.w3b.kdbxfortress.bridge.NativeBridge
import world.w3b.kdbxfortress.storage.VaultDocumentPicker
import world.w3b.kdbxfortress.storage.VaultDocumentSelection
import world.w3b.kdbxfortress.ui.KdbxFortressApp
import world.w3b.kdbxfortress.ui.theme.KdbxFortressTheme
import world.w3b.kdbxfortress.vault.VaultBrowserState
import world.w3b.kdbxfortress.vault.VaultSessionController

class MainActivity : ComponentActivity() {
    private var selectedDocument by mutableStateOf<VaultDocumentSelection?>(null)
    private var selectedKeyFile by mutableStateOf<VaultDocumentSelection?>(null)
    private var browserState by mutableStateOf<VaultBrowserState>(VaultBrowserState.Locked)

    private lateinit var documentPicker: VaultDocumentPicker
    private lateinit var sessionController: VaultSessionController

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        selectedDocument = savedInstanceState?.restoreSelection(VAULT_STATE_PREFIX)
        selectedKeyFile = savedInstanceState?.restoreSelection(KEYFILE_STATE_PREFIX)

        sessionController = VaultSessionController(
            contentResolver = contentResolver,
            postToMain = { operation -> runOnUiThread(operation) },
            onStateChanged = { state -> browserState = state },
        )

        documentPicker = VaultDocumentPicker(
            activity = this,
            onSelected = { selection ->
                sessionController.lockAndReset()
                selectedDocument = selection
                selectedKeyFile = null
            },
            onKeyFileSelected = { selection ->
                sessionController.lockAndReset()
                selectedKeyFile = selection
            },
        )

        val nativeReady = runCatching {
            NativeBridge.verifyRuntimeBoundary()
        }.isSuccess

        setContent {
            KdbxFortressTheme {
                KdbxFortressApp(
                    nativeReady = nativeReady,
                    selectedDocumentName = selectedDocument?.displayName,
                    selectedDocumentPersistent = selectedDocument?.persistentAccess == true,
                    selectedKeyFileName = selectedKeyFile?.displayName,
                    browserState = browserState,
                    onOpenVault = documentPicker::openVault,
                    onSelectKeyFile = documentPicker::openKeyFile,
                    onClearKeyFile = {
                        sessionController.lockAndReset()
                        selectedKeyFile = null
                    },
                    onUnlockVault = { password ->
                        val document = selectedDocument
                        if (document == null) {
                            password.fill(0)
                        } else {
                            sessionController.unlock(
                                vaultDocument = document,
                                password = password,
                                keyFile = selectedKeyFile,
                            )
                        }
                    },
                    onOpenGroup = sessionController::openGroup,
                    onLockVault = sessionController::lockAndReset,
                    onCreateVault = { documentPicker.createVault() },
                    createVaultEnabled = false,
                )
            }
        }
    }

    override fun onStart() {
        super.onStart()
        sessionController.onForegrounded()
    }

    override fun onSaveInstanceState(outState: Bundle) {
        selectedDocument?.saveIfPersistent(outState, VAULT_STATE_PREFIX)
        selectedKeyFile?.saveIfPersistent(outState, KEYFILE_STATE_PREFIX)
        super.onSaveInstanceState(outState)
    }

    override fun onStop() {
        sessionController.onBackgrounded()
        super.onStop()
    }

    override fun onDestroy() {
        sessionController.close()
        super.onDestroy()
    }

    private fun VaultDocumentSelection.saveIfPersistent(outState: Bundle, prefix: String) {
        if (!persistentAccess) return
        outState.putString("${prefix}_uri", uri.toString())
        outState.putString("${prefix}_name", displayName)
        outState.putBoolean("${prefix}_persistent", true)
    }

    private fun Bundle.restoreSelection(prefix: String): VaultDocumentSelection? {
        if (!getBoolean("${prefix}_persistent")) return null
        val uri = getString("${prefix}_uri")?.let(Uri::parse) ?: return null
        val name = getString("${prefix}_name") ?: return null
        return VaultDocumentSelection(
            uri = uri,
            displayName = name,
            persistentAccess = true,
        )
    }

    private companion object {
        const val VAULT_STATE_PREFIX = "vault_document"
        const val KEYFILE_STATE_PREFIX = "keyfile_document"
    }
}
