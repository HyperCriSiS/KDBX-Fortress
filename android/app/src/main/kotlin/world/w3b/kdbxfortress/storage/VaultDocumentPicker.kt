package world.w3b.kdbxfortress.storage

import android.app.Activity
import android.content.ContentResolver
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.OpenableColumns
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContract

private const val KDBX_EXTENSION = ".kdbx"
private const val DEFAULT_VAULT_NAME = "New Vault.kdbx"
private const val MAX_DISPLAY_NAME_LENGTH = 128

private val KDBX_MIME_TYPES = arrayOf(
    "application/octet-stream",
    "application/x-keepass2",
)

data class VaultDocumentSelection(
    val uri: Uri,
    val displayName: String,
    val persistentAccess: Boolean,
)

private data class DocumentGrant(
    val uri: Uri,
    val flags: Int,
)

private class OpenKdbxDocumentContract : ActivityResultContract<Unit, DocumentGrant?>() {
    override fun createIntent(context: Context, input: Unit): Intent =
        Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
            putExtra(Intent.EXTRA_MIME_TYPES, KDBX_MIME_TYPES)
            addFlags(
                Intent.FLAG_GRANT_READ_URI_PERMISSION or
                    Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION,
            )
        }

    override fun parseResult(resultCode: Int, intent: Intent?): DocumentGrant? {
        if (resultCode != Activity.RESULT_OK) return null
        val uri = intent?.data ?: return null
        return DocumentGrant(uri = uri, flags = intent.flags)
    }
}

private class OpenKeyFileDocumentContract : ActivityResultContract<Unit, DocumentGrant?>() {
    override fun createIntent(context: Context, input: Unit): Intent =
        Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
            addFlags(
                Intent.FLAG_GRANT_READ_URI_PERMISSION or
                    Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION,
            )
        }

    override fun parseResult(resultCode: Int, intent: Intent?): DocumentGrant? {
        if (resultCode != Activity.RESULT_OK) return null
        val uri = intent?.data ?: return null
        return DocumentGrant(uri = uri, flags = intent.flags)
    }
}

private class CreateKdbxDocumentContract : ActivityResultContract<String, DocumentGrant?>() {
    override fun createIntent(context: Context, input: String): Intent =
        Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "application/octet-stream"
            putExtra(Intent.EXTRA_TITLE, normalizeVaultName(input))
            addFlags(
                Intent.FLAG_GRANT_READ_URI_PERMISSION or
                    Intent.FLAG_GRANT_WRITE_URI_PERMISSION or
                    Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION,
            )
        }

    override fun parseResult(resultCode: Int, intent: Intent?): DocumentGrant? {
        if (resultCode != Activity.RESULT_OK) return null
        val uri = intent?.data ?: return null
        return DocumentGrant(uri = uri, flags = intent.flags)
    }
}

class VaultDocumentPicker(
    activity: ComponentActivity,
    private val onSelected: (VaultDocumentSelection) -> Unit,
    private val onKeyFileSelected: (VaultDocumentSelection) -> Unit,
) {
    private val contentResolver = activity.contentResolver

    private val openDocument = activity.registerForActivityResult(OpenKdbxDocumentContract()) { grant ->
        grant?.let { onSelected(selectionFor(it, allowWrite = false)) }
    }

    private val openKeyFile =
        activity.registerForActivityResult(OpenKeyFileDocumentContract()) { grant ->
            grant?.let { onKeyFileSelected(selectionFor(it, allowWrite = false)) }
        }

    private val createDocument =
        activity.registerForActivityResult(CreateKdbxDocumentContract()) { grant ->
            grant?.let { onSelected(selectionFor(it, allowWrite = true)) }
        }

    fun openVault() {
        openDocument.launch(Unit)
    }

    fun openKeyFile() {
        openKeyFile.launch(Unit)
    }

    /**
     * The launcher is intentionally wired now so Phase 2 can enable it without changing
     * the storage boundary. Phase 1 keeps the UI action disabled to avoid leaving an empty,
     * invalid .kdbx document before the verified Rust create/write path exists.
     */
    fun createVault(suggestedName: String = DEFAULT_VAULT_NAME) {
        createDocument.launch(normalizeVaultName(suggestedName))
    }

    private fun selectionFor(grant: DocumentGrant, allowWrite: Boolean): VaultDocumentSelection {
        val persistentAccess = persistAccess(grant, allowWrite)
        return VaultDocumentSelection(
            uri = grant.uri,
            displayName = contentResolver.safeDisplayName(grant.uri),
            persistentAccess = persistentAccess,
        )
    }

    private fun persistAccess(grant: DocumentGrant, allowWrite: Boolean): Boolean {
        val allowedFlags = if (allowWrite) {
            Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
        } else {
            Intent.FLAG_GRANT_READ_URI_PERMISSION
        }
        val grantedFlags = grant.flags and allowedFlags
        if (grantedFlags == 0) return false

        return runCatching {
            contentResolver.takePersistableUriPermission(grant.uri, grantedFlags)
            true
        }.getOrDefault(false)
    }
}

private fun ContentResolver.safeDisplayName(uri: Uri): String {
    val displayName = runCatching {
        query(
            uri,
            arrayOf(OpenableColumns.DISPLAY_NAME),
            null,
            null,
            null,
        )?.use { cursor ->
            if (!cursor.moveToFirst()) return@use null
            val index = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (index < 0) null else cursor.getString(index)
        }
    }.getOrNull()

    return sanitizeDisplayName(displayName)
}

private fun sanitizeDisplayName(raw: String?): String {
    val cleaned = raw
        ?.filterNot(Char::isISOControl)
        ?.trim()
        ?.take(MAX_DISPLAY_NAME_LENGTH)
        .orEmpty()
    return cleaned.ifEmpty { "KDBX document" }
}

private fun normalizeVaultName(raw: String): String {
    val cleaned = sanitizeDisplayName(raw)
    return if (cleaned.endsWith(KDBX_EXTENSION, ignoreCase = true)) {
        cleaned
    } else {
        "$cleaned$KDBX_EXTENSION"
    }
}
