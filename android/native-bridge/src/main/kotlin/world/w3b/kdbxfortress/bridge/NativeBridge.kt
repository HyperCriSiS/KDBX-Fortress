package world.w3b.kdbxfortress.bridge

object NativeBridge {
    private const val STATUS_OK = 0L
    private const val STATUS_UNSUPPORTED_REQUEST = 1L
    private const val STATUS_INVALID_HANDLE = -9
    private const val CORE_ABI_REQUEST = 1
    private const val ADAPTER_ABI_REQUEST = 2
    private const val EXPECTED_ADAPTER_ABI = 4L
    const val MAX_PASSWORD_BYTES = 4 * 1024
    const val MAX_KEYFILE_BYTES = 1024 * 1024

    private const val METADATA_REQUEST_VAULT = 1
    private const val METADATA_REQUEST_GROUP = 2
    private const val METADATA_REQUEST_ENTRY = 3
    private const val METADATA_KIND_VAULT = 1
    private const val METADATA_KIND_GROUP = 2
    private const val METADATA_KIND_ENTRY = 3
    private const val METADATA_ID_BYTES = 16
    private const val MAX_METADATA_RESPONSE_BYTES = 256 * 1024
    private const val MAX_METADATA_TEXT_BYTES = 16 * 1024
    private const val MAX_METADATA_TAGS = 128
    private const val MAX_METADATA_TAG_BYTES = 1024
    private const val MAX_METADATA_CHILDREN = 4096

    init {
        System.loadLibrary("kdbx_fortress_android_jni")
    }

    @JvmStatic
    private external fun nativeCapabilityProbe(request: Int): Long

    @JvmStatic
    private external fun nativeOpenVault(
        kdbx: ByteArray,
        password: ByteArray?,
        keyfile: ByteArray?,
    ): Long

    @JvmStatic
    private external fun nativeLockVault(handle: Long): Int

    @JvmStatic
    private external fun nativeIsVaultHandleValid(handle: Long): Int

    @JvmStatic
    private external fun nativeReadMetadata(
        handle: Long,
        request: Int,
        targetId: ByteArray?,
    ): ByteArray?

    @JvmStatic
    private external fun nativeLockAllVaults(): Int

    fun verifyRuntimeBoundary() {
        val core = decode(nativeCapabilityProbe(CORE_ABI_REQUEST))
        check(core.status == STATUS_OK)
        check(core.value > 0L)

        val adapter = decode(nativeCapabilityProbe(ADAPTER_ABI_REQUEST))
        check(adapter.status == STATUS_OK)
        check(adapter.value == EXPECTED_ADAPTER_ABI)

        val unsupported = decode(nativeCapabilityProbe(Int.MAX_VALUE))
        check(unsupported.status == STATUS_UNSUPPORTED_REQUEST)
        check(unsupported.value == 0L)
    }

    fun openVault(
        kdbx: ByteArray,
        password: ByteArray?,
        keyfile: ByteArray?,
    ): Long {
        require(password == null || password.size <= MAX_PASSWORD_BYTES)
        require(keyfile == null || keyfile.size <= MAX_KEYFILE_BYTES)

        val result = nativeOpenVault(kdbx, password, keyfile)
        if (result <= 0L) {
            throw NativeBoundaryException(NativeFailure.fromStatus(result.toInt()))
        }
        return result
    }

    fun lockVault(handle: Long) {
        val status = nativeLockVault(handle)
        if (status != 0) {
            throw NativeBoundaryException(NativeFailure.fromStatus(status))
        }
    }

    fun isVaultHandleValid(handle: Long): Boolean {
        val status = nativeIsVaultHandleValid(handle)
        if (status < 0) {
            throw NativeBoundaryException(NativeFailure.fromStatus(status))
        }
        return status == 1
    }

    fun verifyMalformedHandleBoundary() {
        check(nativeIsVaultHandleValid(0L) == 0)
        check(nativeIsVaultHandleValid(-1L) == 0)
        check(nativeLockVault(0L) == STATUS_INVALID_HANDLE)
        check(nativeLockVault(-1L) == STATUS_INVALID_HANDLE)

        val invalidMetadata = nativeReadMetadata(0L, METADATA_REQUEST_VAULT, null)
        val cursor = metadataCursor(invalidMetadata, expectedKind = 0, requireSuccess = false)
        check(cursor.status == STATUS_INVALID_HANDLE.toLong())
        cursor.requireExhausted()
    }

    fun openLifecycleProbeVaults(kdbx: ByteArray, password: ByteArray): LongArray {
        val handles = LongArray(2)
        try {
            handles[0] = openVault(kdbx, password, null)
            handles[1] = openVault(kdbx, password, null)
            handles.forEach { handle -> check(nativeIsVaultHandleValid(handle) == 1) }
            return handles
        } catch (error: Throwable) {
            nativeLockAllVaults()
            throw error
        }
    }

    fun readVaultSummary(handle: Long): VaultSummary {
        val cursor = metadataCursor(
            nativeReadMetadata(handle, METADATA_REQUEST_VAULT, null),
            expectedKind = METADATA_KIND_VAULT,
        )
        val result = VaultSummary(
            databaseName = cursor.readOptionalText(MAX_METADATA_TEXT_BYTES),
            rootGroupId = cursor.readId(),
            groupCount = cursor.readUnsignedInt(),
            entryCount = cursor.readUnsignedInt(),
            attachmentCount = cursor.readUnsignedInt(),
            hasIgnoredXmlFields = cursor.readBoolean(),
        )
        cursor.requireExhausted()
        return result
    }

    fun readGroupSummary(handle: Long, groupId: MetadataId): GroupSummary {
        val cursor = metadataCursor(
            nativeReadMetadata(handle, METADATA_REQUEST_GROUP, groupId.toNativeBytes()),
            expectedKind = METADATA_KIND_GROUP,
        )
        val id = cursor.readId()
        val parentId = cursor.readOptionalId()
        val name = cursor.readText(MAX_METADATA_TEXT_BYTES)
        val childGroups = List(cursor.readCount(MAX_METADATA_CHILDREN)) { cursor.readId() }
        val entries = List(cursor.readCount(MAX_METADATA_CHILDREN)) { cursor.readId() }
        cursor.requireExhausted()
        return GroupSummary(
            id = id,
            parentId = parentId,
            name = name,
            childGroupIds = childGroups,
            entryIds = entries,
        )
    }

    fun readEntrySummary(handle: Long, entryId: MetadataId): EntrySummary {
        val cursor = metadataCursor(
            nativeReadMetadata(handle, METADATA_REQUEST_ENTRY, entryId.toNativeBytes()),
            expectedKind = METADATA_KIND_ENTRY,
        )
        val id = cursor.readId()
        val parentId = cursor.readId()
        val title = cursor.readOptionalText(MAX_METADATA_TEXT_BYTES)
        val username = cursor.readOptionalText(MAX_METADATA_TEXT_BYTES)
        val url = cursor.readOptionalText(MAX_METADATA_TEXT_BYTES)
        val tags = List(cursor.readCount(MAX_METADATA_TAGS)) {
            cursor.readText(MAX_METADATA_TAG_BYTES)
        }
        val hasPassword = cursor.readBoolean()
        val hasOtp = cursor.readBoolean()
        val attachmentCount = cursor.readUnsignedInt()
        cursor.requireExhausted()
        return EntrySummary(
            id = id,
            parentGroupId = parentId,
            title = title,
            username = username,
            url = url,
            tags = tags,
            hasPassword = hasPassword,
            hasOtp = hasOtp,
            attachmentCount = attachmentCount,
        )
    }

    fun verifyMetadataReadBoundary(handle: Long) {
        val vault = readVaultSummary(handle)
        check(vault.groupCount == 2L)
        check(vault.entryCount == 1L)
        check(vault.attachmentCount == 0L)

        val root = readGroupSummary(handle, vault.rootGroupId)
        check(root.id == vault.rootGroupId)
        check(root.parentId == null)
        check(root.childGroupIds.size == 1)
        check(root.entryIds.isEmpty())

        val group = readGroupSummary(handle, root.childGroupIds.single())
        check(group.parentId == root.id)
        check(group.name == "Synthetic")
        check(group.childGroupIds.isEmpty())
        check(group.entryIds.size == 1)

        val entry = readEntrySummary(handle, group.entryIds.single())
        check(entry.parentGroupId == group.id)
        check(entry.title == "Example Login")
        check(entry.username == "fixture-user")
        check(entry.url == "https://example.test")
        check(entry.tags.isEmpty())
        check(entry.hasPassword)
        check(!entry.hasOtp)
        check(entry.attachmentCount == 0L)
    }

    fun verifyLifecycleLockAll(handles: LongArray) {
        check(handles.isNotEmpty())
        lockAllVaults()
        handles.forEach { handle ->
            check(handle > 0L)
            check(nativeIsVaultHandleValid(handle) == 0)
            // A stale but structurally valid handle remains an idempotent lock.
            check(nativeLockVault(handle) == 0)
        }
        lockAllVaults()
    }

    fun lockAllVaults() {
        check(nativeLockAllVaults() == 0)
    }

    fun lockAllForFailureCleanup() {
        lockAllVaults()
    }

    private fun metadataCursor(
        response: ByteArray?,
        expectedKind: Int,
        requireSuccess: Boolean = true,
    ): MetadataCursor {
        check(response != null) { "nativeReadMetadata failed inside JNI" }
        check(response.size in 9..MAX_METADATA_RESPONSE_BYTES)
        val cursor = MetadataCursor(response)
        check(cursor.readByte() == 'K'.code)
        check(cursor.readByte() == 'F'.code)
        check(cursor.readByte() == 'M'.code)
        check(cursor.readByte() == '1'.code)
        val status = cursor.readInt()
        val kind = cursor.readByte()
        if (requireSuccess && status != 0) {
            throw NativeBoundaryException(NativeFailure.fromStatus(status))
        }
        check(kind == expectedKind)
        cursor.status = status.toLong()
        return cursor
    }

    private fun decode(encoded: Long): Response {
        val status = encoded ushr 32
        val value = encoded and 0xffff_ffffL
        return Response(status = status, value = value)
    }

    class MetadataId internal constructor(bytes: ByteArray) {
        private val bytes = bytes.copyOf()

        init {
            check(this.bytes.size == METADATA_ID_BYTES)
        }

        internal fun toNativeBytes(): ByteArray = bytes.copyOf()

        override fun equals(other: Any?): Boolean =
            other is MetadataId && bytes.contentEquals(other.bytes)

        override fun hashCode(): Int = bytes.contentHashCode()
    }

    enum class NativeFailure(val status: Int) {
        InvalidArgument(-1),
        JniError(-2),
        InvalidCredentialMaterial(-3),
        InvalidInput(-4),
        UnsupportedFormat(-5),
        ResourceLimit(-6),
        OpenRejected(-7),
        CapacityExceeded(-8),
        InvalidHandle(-9),
        Internal(-10),
        PanicContained(-11),
        NotFound(-12),
        Unknown(Int.MIN_VALUE);

        companion object {
            internal fun fromStatus(status: Int): NativeFailure =
                entries.firstOrNull { it.status == status } ?: Unknown
        }
    }

    class NativeBoundaryException(
        val failure: NativeFailure,
    ) : IllegalStateException("native vault operation failed: ${failure.name}")

    data class VaultSummary(
        val databaseName: String?,
        val rootGroupId: MetadataId,
        val groupCount: Long,
        val entryCount: Long,
        val attachmentCount: Long,
        val hasIgnoredXmlFields: Boolean,
    )

    data class GroupSummary(
        val id: MetadataId,
        val parentId: MetadataId?,
        val name: String,
        val childGroupIds: List<MetadataId>,
        val entryIds: List<MetadataId>,
    )

    data class EntrySummary(
        val id: MetadataId,
        val parentGroupId: MetadataId,
        val title: String?,
        val username: String?,
        val url: String?,
        val tags: List<String>,
        val hasPassword: Boolean,
        val hasOtp: Boolean,
        val attachmentCount: Long,
    )

    private class MetadataCursor(private val bytes: ByteArray) {
        private var offset = 0
        var status: Long = 0

        fun readByte(): Int {
            requireAvailable(1)
            return bytes[offset++].toInt() and 0xff
        }

        fun readInt(): Int {
            val b0 = readByte()
            val b1 = readByte()
            val b2 = readByte()
            val b3 = readByte()
            return b0 or (b1 shl 8) or (b2 shl 16) or (b3 shl 24)
        }

        fun readUnsignedInt(): Long = readInt().toLong() and 0xffff_ffffL

        fun readCount(maximum: Int): Int {
            val count = readUnsignedInt()
            check(count <= maximum.toLong())
            return count.toInt()
        }

        fun readBoolean(): Boolean = when (readByte()) {
            0 -> false
            1 -> true
            else -> error("invalid metadata boolean")
        }

        fun readId(): MetadataId {
            requireAvailable(METADATA_ID_BYTES)
            val result = MetadataId(bytes.copyOfRange(offset, offset + METADATA_ID_BYTES))
            offset += METADATA_ID_BYTES
            return result
        }

        fun readOptionalId(): MetadataId? = when (readByte()) {
            0 -> null
            1 -> readId()
            else -> error("invalid optional metadata id")
        }

        fun readText(maximumBytes: Int): String {
            val length = readCount(maximumBytes)
            requireAvailable(length)
            val result = String(bytes, offset, length, Charsets.UTF_8)
            offset += length
            return result
        }

        fun readOptionalText(maximumBytes: Int): String? = when (readByte()) {
            0 -> null
            1 -> readText(maximumBytes)
            else -> error("invalid optional metadata text")
        }

        fun requireExhausted() {
            check(offset == bytes.size)
        }

        private fun requireAvailable(length: Int) {
            check(length >= 0)
            check(offset <= bytes.size - length)
        }
    }

    private data class Response(val status: Long, val value: Long)
}
