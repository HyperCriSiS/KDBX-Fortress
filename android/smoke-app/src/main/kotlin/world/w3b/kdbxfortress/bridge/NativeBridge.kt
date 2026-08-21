package world.w3b.kdbxfortress.bridge

internal object NativeBridge {
    private const val STATUS_OK = 0L
    private const val STATUS_UNSUPPORTED_REQUEST = 1L
    private const val STATUS_INVALID_HANDLE = -9
    private const val CORE_ABI_REQUEST = 1
    private const val ADAPTER_ABI_REQUEST = 2
    private const val EXPECTED_ADAPTER_ABI = 2L

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

    fun verifyVaultLifecycle(kdbx: ByteArray, password: ByteArray) {
        val handle = nativeOpenVault(kdbx, password, null)
        check(handle > 0L) { "nativeOpenVault failed with status $handle" }
        check(nativeIsVaultHandleValid(handle) == 1)

        check(nativeLockVault(handle) == 0)
        check(nativeIsVaultHandleValid(handle) == 0)

        // Lock stays idempotent for a structurally valid stale handle.
        check(nativeLockVault(handle) == 0)
        check(nativeIsVaultHandleValid(0L) == 0)
        check(nativeLockVault(0L) == STATUS_INVALID_HANDLE)
    }

    private fun decode(encoded: Long): Response {
        val status = encoded ushr 32
        val value = encoded and 0xffff_ffffL
        return Response(status = status, value = value)
    }

    private data class Response(val status: Long, val value: Long)
}
