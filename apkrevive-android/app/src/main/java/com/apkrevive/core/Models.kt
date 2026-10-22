package com.apkrevive.core

enum class Verdict {
    GREEN,
    YELLOW,
    RED,
    NEEDS_USER_INPUT
}

enum class TriageSignal {
    RUNNABLE_UNMODIFIED,
    INCOMPATIBLE_DEVICE_ABI,
    UNRESOLVABLE_SYSTEM_LIBRARY,
    INCOMPATIBLE_PAGE_SIZE,
    EXCEEDS_2GB_LIMIT_FOR_REPACKING,
    MODIFICATION_REQUIRED,
    SIGNATURE_VERIFICATION_DETECTED,
    NEEDS_APACHE_HTTP_LEGACY,
    NEEDS_PILLARBOX_FIX,
    NEEDS_REFRESH_RATE_FIX,
    NEEDS_PAGE_SIZE_COMPAT,
    NEEDS_PAGE_SIZE_COMPAT_ANDROID16,
    NEEDS_HAS_CODE_FLAG,
    SPLIT_APK_UNSUPPORTED
}

data class DeviceProfile(
    val osApiLevel: Int = 35,
    val installFloor: Int = 24,
    val supportedAbis: List<String> = listOf("arm64-v8a"),
    val pageSizeBytes: Long = 16384L,
    val isWidescreen: Boolean = true,
    val isHighRefresh: Boolean = false
)

data class ApkMetadata(
    val packageName: String = "",
    val targetSdk: Int = 1,
    val minSdk: Int = 1,
    val versionCode: Long = 1L,
    val abis: List<String> = emptyList(),
    val elfLoadAlign64bit: Long? = null,
    val privateLibs: List<String> = emptyList(),
    val usesApacheHttp: Boolean = false,
    val hasApacheLibraryDecl: Boolean = false,
    val isSplitApk: Boolean = false,
    val hasInvalidElfLayout: Boolean = false,
    val usesCleartextTraffic: Boolean? = null,
    val hasNetworkSecurityConfig: Boolean = false,
    val legacyTlsProtocols: List<String> = emptyList(),
    val permissions: List<String> = emptyList(),
    val hasCode: Boolean = true,
    val isNonResizeable: Boolean = false,
    val hasFixedPhysics: Boolean = false,
    val hasSelfSigCheck: Boolean = false,
    val hasDrm: Boolean = false,
    val sizeBytes: Long = 0L,
    val staticRemovedApis: List<String> = emptyList()
)

data class TriageResult(
    val verdict: Verdict,
    val reason: TriageSignal,
    val details: String = "",
    val warnings: List<String> = emptyList(),
    val requiredTransforms: List<String> = emptyList(),
    val installMethod: String? = null
) {
    val verdictName: String get() = verdict.name
    val reasonName: String get() = reason.name
}

data class PatchReport(
    val timestamp: String,
    val apkPath: String,
    val packageName: String,
    val targetSdk: Int,
    val verdict: String,
    val reason: String,
    val installMethod: String? = null,
    val requiredTransforms: List<String> = emptyList(),
    val warnings: List<String> = emptyList(),
    val details: String = "",
    val outputApk: String? = null
)
