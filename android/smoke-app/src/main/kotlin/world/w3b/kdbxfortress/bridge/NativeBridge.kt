package world.w3b.kdbxfortress.bridge

internal object NativeBridge {
    private const val STATUS_OK = 0L
    private const val STATUS_UNSUPPORTED_REQUEST = 1L
    private const val CORE_ABI_REQUEST = 1
    private const val ADAPTER_ABI_REQUEST = 2
    private const val EXPECTED_ADAPTER_ABI = 1L

    init {
        System.loadLibrary("kdbx_fortress_android_jni")
    }

    @JvmStatic
    private external fun nativeCapabilityProbe(request: Int): Long

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

    private fun decode(encoded: Long): Response {
        val status = encoded ushr 32
        val value = encoded and 0xffff_ffffL
        return Response(status = status, value = value)
    }

    private data class Response(
        val status: Long,
        val value: Long,
    )
}
