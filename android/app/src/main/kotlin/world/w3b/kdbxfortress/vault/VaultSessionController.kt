package world.w3b.kdbxfortress.vault

import android.content.ContentResolver
import world.w3b.kdbxfortress.bridge.NativeBridge
import world.w3b.kdbxfortress.storage.VaultDocumentReadException
import world.w3b.kdbxfortress.storage.VaultDocumentSelection
import world.w3b.kdbxfortress.storage.readKeyFileBytes
import world.w3b.kdbxfortress.storage.readVaultBytes
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicLong

sealed interface VaultBrowserState {
    data object Locked : VaultBrowserState

    data object Loading : VaultBrowserState

    data class Open(
        val vault: NativeBridge.VaultSummary,
        val group: NativeBridge.GroupSummary,
        val childGroups: List<NativeBridge.GroupSummary>,
        val entries: List<NativeBridge.EntrySummary>,
    ) : VaultBrowserState

    data class Failure(
        val reason: VaultBrowserFailure,
    ) : VaultBrowserState
}

enum class VaultBrowserFailure {
    VaultTooLarge,
    KeyFileTooLarge,
    DocumentUnavailable,
    DocumentReadFailed,
    CredentialTooLarge,
    CredentialsRejected,
    UnsupportedFormat,
    ResourceLimit,
    InvalidInput,
    CapacityExceeded,
    PageTooLarge,
    MetadataUnavailable,
    CoreFailure,
}

class VaultSessionController(
    private val contentResolver: ContentResolver,
    private val postToMain: ((() -> Unit) -> Unit),
    private val onStateChanged: (VaultBrowserState) -> Unit,
) : AutoCloseable {
    private val executor: ExecutorService = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "kdbx-fortress-vault").apply { isDaemon = true }
    }
    private val operationEpoch = AtomicLong(0L)
    private val sessionLock = Any()

    @Volatile
    private var foreground = true

    private var liveHandle = 0L
    private var liveVaultSummary: NativeBridge.VaultSummary? = null

    fun unlock(
        vaultDocument: VaultDocumentSelection,
        password: ByteArray,
        keyFile: VaultDocumentSelection?,
    ) {
        val token = beginOperation()
        publish(token, VaultBrowserState.Loading)

        executor.execute {
            var vaultBytes: ByteArray? = null
            var keyFileBytes: ByteArray? = null
            var newHandle = 0L

            try {
                if (password.size > NativeBridge.MAX_PASSWORD_BYTES) {
                    throw BrowserFailure(VaultBrowserFailure.CredentialTooLarge)
                }

                vaultBytes = readVault(vaultDocument)
                keyFileBytes = keyFile?.let(::readKeyFile)

                if (!isCurrent(token)) return@execute

                newHandle = NativeBridge.openVault(
                    kdbx = vaultBytes,
                    password = password,
                    keyfile = keyFileBytes,
                )

                if (!isCurrent(token)) {
                    safeLock(newHandle)
                    newHandle = 0L
                    return@execute
                }

                val vault = NativeBridge.readVaultSummary(newHandle)
                val page = loadPage(newHandle, vault, vault.rootGroupId)

                if (!isCurrent(token)) {
                    safeLock(newHandle)
                    newHandle = 0L
                    return@execute
                }

                val oldHandle = synchronized(sessionLock) {
                    val previous = liveHandle
                    liveHandle = newHandle
                    liveVaultSummary = vault
                    previous
                }
                newHandle = 0L
                if (oldHandle > 0L) safeLock(oldHandle)

                publish(token, page)
            } catch (error: BrowserFailure) {
                publish(token, VaultBrowserState.Failure(error.reason))
            } catch (error: NativeBridge.NativeBoundaryException) {
                publish(token, VaultBrowserState.Failure(mapNativeFailure(error.failure)))
            } catch (_: RuntimeException) {
                publish(token, VaultBrowserState.Failure(VaultBrowserFailure.CoreFailure))
            } finally {
                if (newHandle > 0L) safeLock(newHandle)
                password.fill(0)
                keyFileBytes?.fill(0)
                vaultBytes?.fill(0)
            }
        }
    }

    fun openGroup(groupId: NativeBridge.MetadataId) {
        val token = beginOperation()
        val session = synchronized(sessionLock) {
            val vault = liveVaultSummary
            if (liveHandle > 0L && vault != null) liveHandle to vault else null
        }

        if (session == null) {
            publish(token, VaultBrowserState.Locked)
            return
        }

        executor.execute {
            try {
                if (!isCurrent(token)) return@execute
                val page = loadPage(session.first, session.second, groupId)
                publish(token, page)
            } catch (error: BrowserFailure) {
                failBrowse(token, error.reason)
            } catch (error: NativeBridge.NativeBoundaryException) {
                val failure = if (error.failure == NativeBridge.NativeFailure.InvalidHandle) {
                    VaultBrowserFailure.MetadataUnavailable
                } else {
                    mapNativeFailure(error.failure)
                }
                failBrowse(token, failure)
            } catch (_: RuntimeException) {
                failBrowse(token, VaultBrowserFailure.CoreFailure)
            }
        }
    }

    fun lockAndReset() {
        operationEpoch.incrementAndGet()
        clearSession()
        runCatching { NativeBridge.lockAllVaults() }
        publishImmediate(VaultBrowserState.Locked)
    }

    fun onForegrounded() {
        foreground = true
    }

    fun onBackgrounded() {
        foreground = false
        operationEpoch.incrementAndGet()
        clearSession()
        runCatching { NativeBridge.lockAllVaults() }
        publishImmediate(VaultBrowserState.Locked)
    }

    override fun close() {
        foreground = false
        operationEpoch.incrementAndGet()
        clearSession()
        runCatching { NativeBridge.lockAllVaults() }
        executor.shutdownNow()
    }

    private fun loadPage(
        handle: Long,
        vault: NativeBridge.VaultSummary,
        groupId: NativeBridge.MetadataId,
    ): VaultBrowserState.Open {
        val group = NativeBridge.readGroupSummary(handle, groupId)
        val directItems = group.childGroupIds.size + group.entryIds.size
        if (directItems > MAX_BROWSER_PAGE_ITEMS) {
            throw BrowserFailure(VaultBrowserFailure.PageTooLarge)
        }

        val childGroups = group.childGroupIds.map { childId ->
            NativeBridge.readGroupSummary(handle, childId)
        }
        val entries = group.entryIds.map { entryId ->
            NativeBridge.readEntrySummary(handle, entryId)
        }

        return VaultBrowserState.Open(
            vault = vault,
            group = group,
            childGroups = childGroups,
            entries = entries,
        )
    }

    private fun readVault(selection: VaultDocumentSelection): ByteArray = try {
        contentResolver.readVaultBytes(selection.uri)
    } catch (error: VaultDocumentReadException) {
        throw BrowserFailure(mapDocumentFailure(error, keyFile = false))
    }

    private fun readKeyFile(selection: VaultDocumentSelection): ByteArray = try {
        contentResolver.readKeyFileBytes(selection.uri)
    } catch (error: VaultDocumentReadException) {
        throw BrowserFailure(mapDocumentFailure(error, keyFile = true))
    }

    private fun beginOperation(): Long = operationEpoch.incrementAndGet()

    private fun isCurrent(token: Long): Boolean =
        foreground && operationEpoch.get() == token

    private fun publish(token: Long, state: VaultBrowserState) {
        if (!isCurrent(token)) return
        postToMain {
            if (isCurrent(token)) onStateChanged(state)
        }
    }

    private fun publishImmediate(state: VaultBrowserState) {
        postToMain { onStateChanged(state) }
    }

    private fun failBrowse(token: Long, reason: VaultBrowserFailure) {
        if (!isCurrent(token)) return
        clearSession()
        runCatching { NativeBridge.lockAllVaults() }
        publish(token, VaultBrowserState.Failure(reason))
    }

    private fun clearSession() {
        synchronized(sessionLock) {
            liveHandle = 0L
            liveVaultSummary = null
        }
    }

    private fun safeLock(handle: Long) {
        runCatching { NativeBridge.lockVault(handle) }
    }

    private fun mapDocumentFailure(
        error: VaultDocumentReadException,
        keyFile: Boolean,
    ): VaultBrowserFailure = when (error.reason) {
        VaultDocumentReadException.Reason.TooLarge -> if (keyFile) {
            VaultBrowserFailure.KeyFileTooLarge
        } else {
            VaultBrowserFailure.VaultTooLarge
        }
        VaultDocumentReadException.Reason.Unavailable -> VaultBrowserFailure.DocumentUnavailable
        VaultDocumentReadException.Reason.ReadFailed -> VaultBrowserFailure.DocumentReadFailed
    }

    private fun mapNativeFailure(failure: NativeBridge.NativeFailure): VaultBrowserFailure =
        when (failure) {
            NativeBridge.NativeFailure.InvalidCredentialMaterial,
            NativeBridge.NativeFailure.OpenRejected -> VaultBrowserFailure.CredentialsRejected

            NativeBridge.NativeFailure.UnsupportedFormat -> VaultBrowserFailure.UnsupportedFormat
            NativeBridge.NativeFailure.ResourceLimit -> VaultBrowserFailure.ResourceLimit
            NativeBridge.NativeFailure.InvalidArgument,
            NativeBridge.NativeFailure.InvalidInput -> VaultBrowserFailure.InvalidInput

            NativeBridge.NativeFailure.CapacityExceeded -> VaultBrowserFailure.CapacityExceeded
            NativeBridge.NativeFailure.NotFound,
            NativeBridge.NativeFailure.InvalidHandle -> VaultBrowserFailure.MetadataUnavailable

            NativeBridge.NativeFailure.JniError,
            NativeBridge.NativeFailure.Internal,
            NativeBridge.NativeFailure.PanicContained,
            NativeBridge.NativeFailure.Unknown -> VaultBrowserFailure.CoreFailure
        }

    private class BrowserFailure(
        val reason: VaultBrowserFailure,
    ) : RuntimeException()

    private companion object {
        const val MAX_BROWSER_PAGE_ITEMS = 1024
    }
}
