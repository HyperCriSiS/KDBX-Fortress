package world.w3b.kdbxfortress.storage

import android.content.ContentResolver
import android.net.Uri
import android.provider.OpenableColumns
import java.io.ByteArrayOutputStream

const val MAX_ANDROID_VAULT_BYTES: Long = 64L * 1024 * 1024
const val MAX_ANDROID_KEYFILE_BYTES: Long = 1024L * 1024

class VaultDocumentReadException(
    val reason: Reason,
) : Exception(reason.name) {
    enum class Reason {
        TooLarge,
        Unavailable,
        ReadFailed,
    }
}

fun ContentResolver.readVaultBytes(uri: Uri): ByteArray =
    readBoundedBytes(uri, MAX_ANDROID_VAULT_BYTES)

fun ContentResolver.readKeyFileBytes(uri: Uri): ByteArray =
    readBoundedBytes(uri, MAX_ANDROID_KEYFILE_BYTES)

private fun ContentResolver.readBoundedBytes(uri: Uri, maximumBytes: Long): ByteArray {
    require(maximumBytes in 1..Int.MAX_VALUE.toLong())

    val declaredSize = queryDeclaredSize(uri)
    if (declaredSize != null && declaredSize > maximumBytes) {
        throw VaultDocumentReadException(VaultDocumentReadException.Reason.TooLarge)
    }

    val initialCapacity = declaredSize
        ?.takeIf { it > 0L }
        ?.coerceAtMost(maximumBytes)
        ?.toInt()
        ?: DEFAULT_BUFFER_BYTES

    val output = ZeroingByteArrayOutputStream(initialCapacity)
    val buffer = ByteArray(DEFAULT_BUFFER_BYTES)

    try {
        val input = try {
            openInputStream(uri)
        } catch (_: RuntimeException) {
            null
        } ?: throw VaultDocumentReadException(VaultDocumentReadException.Reason.Unavailable)

        input.use { stream ->
            var total = 0L
            while (true) {
                val read = try {
                    stream.read(buffer)
                } catch (_: Exception) {
                    throw VaultDocumentReadException(VaultDocumentReadException.Reason.ReadFailed)
                }
                if (read < 0) break
                if (read == 0) continue

                total += read.toLong()
                if (total > maximumBytes) {
                    throw VaultDocumentReadException(VaultDocumentReadException.Reason.TooLarge)
                }
                output.write(buffer, 0, read)
            }
        }

        return output.copyAndClear()
    } finally {
        buffer.fill(0)
        output.clearBuffer()
    }
}

private fun ContentResolver.queryDeclaredSize(uri: Uri): Long? = runCatching {
    query(
        uri,
        arrayOf(OpenableColumns.SIZE),
        null,
        null,
        null,
    )?.use { cursor ->
        if (!cursor.moveToFirst()) return@use null
        val index = cursor.getColumnIndex(OpenableColumns.SIZE)
        if (index < 0 || cursor.isNull(index)) null else cursor.getLong(index).takeIf { it >= 0L }
    }
}.getOrNull()

private class ZeroingByteArrayOutputStream(initialCapacity: Int) :
    ByteArrayOutputStream(initialCapacity.coerceAtLeast(1)) {
    fun copyAndClear(): ByteArray {
        val result = toByteArray()
        clearBuffer()
        return result
    }

    fun clearBuffer() {
        buf.fill(0)
        reset()
    }
}

private const val DEFAULT_BUFFER_BYTES = 16 * 1024
