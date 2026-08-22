package world.w3b.kdbxfortress

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

class MainActivity : ComponentActivity() {
    private var selectedDocument by mutableStateOf<VaultDocumentSelection?>(null)
    private lateinit var documentPicker: VaultDocumentPicker

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        selectedDocument = savedInstanceState?.restoreDocumentSelection()
        documentPicker = VaultDocumentPicker(this) { selection ->
            selectedDocument = selection
        }

        val nativeReady = runCatching {
            NativeBridge.verifyRuntimeBoundary()
        }.isSuccess

        setContent {
            KdbxFortressTheme {
                KdbxFortressApp(
                    nativeReady = nativeReady,
                    selectedDocumentName = selectedDocument?.displayName,
                    selectedDocumentPersistent = selectedDocument?.persistentAccess == true,
                    onOpenVault = documentPicker::openVault,
                    onCreateVault = { documentPicker.createVault() },
                    createVaultEnabled = false,
                )
            }
        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        selectedDocument?.let { selection ->
            outState.putString(STATE_DOCUMENT_URI, selection.uri.toString())
            outState.putString(STATE_DOCUMENT_NAME, selection.displayName)
            outState.putBoolean(STATE_DOCUMENT_PERSISTENT, selection.persistentAccess)
        }
        super.onSaveInstanceState(outState)
    }

    override fun onStop() {
        runCatching { NativeBridge.lockAllVaults() }
        super.onStop()
    }

    private fun Bundle.restoreDocumentSelection(): VaultDocumentSelection? {
        val uri = getString(STATE_DOCUMENT_URI)?.let { android.net.Uri.parse(it) } ?: return null
        val name = getString(STATE_DOCUMENT_NAME) ?: return null
        return VaultDocumentSelection(
            uri = uri,
            displayName = name,
            persistentAccess = getBoolean(STATE_DOCUMENT_PERSISTENT),
        )
    }

    private companion object {
        const val STATE_DOCUMENT_URI = "vault_document_uri"
        const val STATE_DOCUMENT_NAME = "vault_document_name"
        const val STATE_DOCUMENT_PERSISTENT = "vault_document_persistent"
    }
}
