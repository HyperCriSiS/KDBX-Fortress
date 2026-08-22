package world.w3b.kdbxfortress.bridge

internal object NativeBridge {
    private const val STATUS_OK = 0L
    private const val STATUS_UNSUPPORTED_REQUEST = 1L
    private const val STATUS_INVALID_HANDLE = -9
    private const val CORE_ABI_REQUEST = 1
    private const val ADAPTER_ABI_REQUEST = 2
    private const val EXPECTED_ADAPTER_ABI = 3L

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

    fun verifyInvalidAndStaleHandleBehavior(kdbx: ByteArray, password: ByteArray) {
        check(nativeIsVaultHandleValid(0L) == 0)
        check(nativeIsVaultHandleValid(-1L) == 0)
        check(nativeLockVault(0L) == STATUS_INVALID_HANDLE)
        check(nativeLockVault(-1L) == STATUS_INVALID_HANDLE)

        val first = openVault(kdbx, password)
        check(nativeIsVaultHandleValid(first) == 1)
        check(nativeLockVault(first) == 0)
        check(nativeIsVaultHandleValid(first) == 0)

        val second = openVault(kdbx, password)
        try {
            // The first vacant registry slot is deliberately reused with a new
            // generation. The stale capability must never become live again.
            check(second != first)
            check(nativeIsVaultHandleValid(first) == 0)
            check(nativeIsVaultHandleValid(second) == 1)
            check(nativeLockVault(first) == 0)
            check(nativeIsVaultHandleValid(second) == 1)
        } finally {
            check(nativeLockVault(second) == 0)
        }
    }

    fun openLifecycleProbeVaults(kdbx: ByteArray, password: ByteArray): LongArray {
        val handles = LongArray(2)
        try {
            handles[0] = openVault(kdbx, password)
            handles[1] = openVault(kdbx, password)
            handles.forEach { handle -> check(nativeIsVaultHandleValid(handle) == 1) }
            return handles
        } catch (error: Throwable) {
            nativeLockAllVaults()
            throw error
        }
    }

    fun verifyLifecycleLockAll(handles: LongArray) {
        check(handles.isNotEmpty())
        check(nativeLockAllVaults() == 0)
        handles.forEach { handle ->
            check(handle > 0L)
            check(nativeIsVaultHandleValid(handle) == 0)
            // A stale but structurally valid handle remains an idempotent lock.
            check(nativeLockVault(handle) == 0)
        }
        check(nativeLockAllVaults() == 0)
    }

    fun lockAllForFailureCleanup() {
        check(nativeLockAllVaults() == 0)
    }

    private fun openVault(kdbx: ByteArray, password: ByteArray): Long {
        val handle = nativeOpenVault(kdbx, password, null)
        check(handle > 0L) { "nativeOpenVault failed with status $handle" }
        return handle
    }

    private fun decode(encoded: Long): Response {
        val status = encoded ushr 32
        val value = encoded and 0xffff_ffffL
        return Response(status = status, value = value)
    }

    private data class Response(val status: Long, val value: Long)
}
