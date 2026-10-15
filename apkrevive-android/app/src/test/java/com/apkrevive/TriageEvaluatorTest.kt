package com.apkrevive

import com.apkrevive.core.ApkMetadata
import com.apkrevive.core.DeviceProfile
import com.apkrevive.core.TriageEvaluator
import com.apkrevive.core.TriageSignal
import com.apkrevive.core.Verdict
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class TriageEvaluatorTest {

    data class TriageVector(
        val id: String,
        val apk: ApkMetadata,
        val device: DeviceProfile,
        val expectedVerdict: Verdict,
        val expectedReason: TriageSignal,
        val expectedInstallMethod: String? = null,
        val expectedRequiredTransforms: List<String>? = null
    )

    private val vectors = listOf(
        // Vector 01: pure Java targetSdk 28 on API 35 (floor 24) -> Direct install
        TriageVector(
            id = "vector_01_pure_java_targetsdk28",
            apk = ApkMetadata(
                targetSdk = 28,
                abis = emptyList(),
                sizeBytes = 5_000_000L
            ),
            device = DeviceProfile(
                osApiLevel = 35,
                installFloor = 24,
                supportedAbis = listOf("arm64-v8a"),
                pageSizeBytes = 16384L
            ),
            expectedVerdict = Verdict.GREEN,
            expectedReason = TriageSignal.RUNNABLE_UNMODIFIED,
            expectedInstallMethod = "DIRECT_INSTALL"
        ),

        // Vector 02: pure Java targetSdk 22 on API 35 (floor 24) -> Bypass low target SDK block
        TriageVector(
            id = "vector_02_pure_java_targetsdk22",
            apk = ApkMetadata(
                targetSdk = 22,
                abis = emptyList(),
                sizeBytes = 5_000_000L
            ),
            device = DeviceProfile(
                osApiLevel = 35,
                installFloor = 24,
                supportedAbis = listOf("arm64-v8a"),
                pageSizeBytes = 16384L
            ),
            expectedVerdict = Verdict.GREEN,
            expectedReason = TriageSignal.RUNNABLE_UNMODIFIED,
            expectedInstallMethod = "BYPASS_LOW_TARGET_SDK_BLOCK"
        ),

        // Vector 03: 32-bit ARM on 64-bit-only device -> Incompatible device ABI
        TriageVector(
            id = "vector_03_arm32_on_64bit_only",
            apk = ApkMetadata(
                targetSdk = 22,
                abis = listOf("armeabi-v7a"),
                sizeBytes = 15_000_000L
            ),
            device = DeviceProfile(
                osApiLevel = 35,
                installFloor = 24,
                supportedAbis = listOf("arm64-v8a"),
                pageSizeBytes = 16384L
            ),
            expectedVerdict = Verdict.RED,
            expectedReason = TriageSignal.INCOMPATIBLE_DEVICE_ABI
        ),

        // Vector 04: 32-bit ARM on 32-bit capable device -> Direct install
        TriageVector(
            id = "vector_04_arm32_on_32bit_capable",
            apk = ApkMetadata(
                targetSdk = 22,
                abis = listOf("armeabi-v7a"),
                sizeBytes = 15_000_000L
            ),
            device = DeviceProfile(
                osApiLevel = 33,
                installFloor = 1,
                supportedAbis = listOf("arm64-v8a", "armeabi-v7a"),
                pageSizeBytes = 4096L
            ),
            expectedVerdict = Verdict.GREEN,
            expectedReason = TriageSignal.RUNNABLE_UNMODIFIED,
            expectedInstallMethod = "DIRECT_INSTALL"
        ),

        // Vector 05: targetSdk 22 with Apache HTTP control -> Bypass low target SDK block
        TriageVector(
            id = "vector_05_apache_http_targetsdk22_control",
            apk = ApkMetadata(
                targetSdk = 22,
                abis = emptyList(),
                usesApacheHttp = true,
                sizeBytes = 8_000_000L
            ),
            device = DeviceProfile(
                osApiLevel = 35,
                installFloor = 24,
                supportedAbis = listOf("arm64-v8a"),
                pageSizeBytes = 16384L
            ),
            expectedVerdict = Verdict.GREEN,
            expectedReason = TriageSignal.RUNNABLE_UNMODIFIED,
            expectedInstallMethod = "BYPASS_LOW_TARGET_SDK_BLOCK"
        ),

        // Vector 06: targetSdk 28 with Apache HTTP failing -> Needs library inject
        TriageVector(
            id = "vector_06_apache_http_targetsdk28_failing",
            apk = ApkMetadata(
                targetSdk = 28,
                abis = emptyList(),
                usesApacheHttp = true,
                sizeBytes = 8_000_000L
            ),
            device = DeviceProfile(
                osApiLevel = 35,
                installFloor = 24,
                supportedAbis = listOf("arm64-v8a"),
                pageSizeBytes = 16384L
            ),
            expectedVerdict = Verdict.YELLOW,
            expectedReason = TriageSignal.MODIFICATION_REQUIRED,
            expectedRequiredTransforms = listOf("INJECT_USES_LIBRARY_APACHE_HTTP")
        ),

        // Vector 07: 4KB ELF on 16KB kernel Android 15 (API 35) -> Incompatible page size
        TriageVector(
            id = "vector_07_elf_4kb_on_16kb_android15",
            apk = ApkMetadata(
                targetSdk = 28,
                abis = listOf("arm64-v8a"),
                elfLoadAlign64bit = 4096L,
                sizeBytes = 25_000_000L
            ),
            device = DeviceProfile(
                osApiLevel = 35,
                installFloor = 24,
                supportedAbis = listOf("arm64-v8a"),
                pageSizeBytes = 16384L
            ),
            expectedVerdict = Verdict.RED,
            expectedReason = TriageSignal.INCOMPATIBLE_PAGE_SIZE
        ),

        // Vector 08: 4KB ELF on 16KB kernel Android 16 (API 36) -> Page size compat transform
        TriageVector(
            id = "vector_08_elf_4kb_on_16kb_android16",
            apk = ApkMetadata(
                targetSdk = 28,
                abis = listOf("arm64-v8a"),
                elfLoadAlign64bit = 4096L,
                sizeBytes = 25_000_000L
            ),
            device = DeviceProfile(
                osApiLevel = 36,
                installFloor = 24,
                supportedAbis = listOf("arm64-v8a"),
                pageSizeBytes = 16384L
            ),
            expectedVerdict = Verdict.YELLOW,
            expectedReason = TriageSignal.MODIFICATION_REQUIRED,
            expectedRequiredTransforms = listOf("PAGE_SIZE_COMPAT")
        ),

        // Vector 09: Private lib greylisted targetSdk 22 -> Runnable unmodified
        TriageVector(
            id = "vector_09_private_lib_greylisted_targetsdk22",
            apk = ApkMetadata(
                targetSdk = 22,
                abis = listOf("arm64-v8a"),
                elfLoadAlign64bit = 16384L,
                privateLibs = listOf("libcrypto.so"),
                sizeBytes = 10_000_000L
            ),
            device = DeviceProfile(
                osApiLevel = 35,
                installFloor = 24,
                supportedAbis = listOf("arm64-v8a"),
                pageSizeBytes = 16384L
            ),
            expectedVerdict = Verdict.GREEN,
            expectedReason = TriageSignal.RUNNABLE_UNMODIFIED
        ),

        // Vector 10: Private lib greylisted targetSdk 26 -> Unresolvable system library
        TriageVector(
            id = "vector_10_private_lib_greylisted_targetsdk26",
            apk = ApkMetadata(
                targetSdk = 26,
                abis = listOf("arm64-v8a"),
                elfLoadAlign64bit = 16384L,
                privateLibs = listOf("libcrypto.so"),
                sizeBytes = 10_000_000L
            ),
            device = DeviceProfile(
                osApiLevel = 35,
                installFloor = 24,
                supportedAbis = listOf("arm64-v8a"),
                pageSizeBytes = 16384L
            ),
            expectedVerdict = Verdict.RED,
            expectedReason = TriageSignal.UNRESOLVABLE_SYSTEM_LIBRARY
        ),

        // Vector 11: Private lib non-greylisted -> Unresolvable system library
        TriageVector(
            id = "vector_11_private_lib_non_greylisted",
            apk = ApkMetadata(
                targetSdk = 22,
                abis = listOf("arm64-v8a"),
                elfLoadAlign64bit = 16384L,
                privateLibs = listOf("libgui.so"),
                sizeBytes = 10_000_000L
            ),
            device = DeviceProfile(
                osApiLevel = 35,
                installFloor = 24,
                supportedAbis = listOf("arm64-v8a"),
                pageSizeBytes = 16384L
            ),
            expectedVerdict = Verdict.RED,
            expectedReason = TriageSignal.UNRESOLVABLE_SYSTEM_LIBRARY
        ),

        // Vector 12: DRM detected warning -> Green with warning
        TriageVector(
            id = "vector_12_drm_detected_warning",
            apk = ApkMetadata(
                targetSdk = 28,
                abis = emptyList(),
                hasDrm = true,
                sizeBytes = 12_000_000L
            ),
            device = DeviceProfile(
                osApiLevel = 35,
                installFloor = 24,
                supportedAbis = listOf("arm64-v8a"),
                pageSizeBytes = 16384L
            ),
            expectedVerdict = Verdict.GREEN,
            expectedReason = TriageSignal.RUNNABLE_UNMODIFIED
        ),

        // Vector 13: Exceeds 2GB unmodified -> Runnable unmodified
        TriageVector(
            id = "vector_13_exceeds_2gb_unmodified",
            apk = ApkMetadata(
                targetSdk = 28,
                abis = emptyList(),
                sizeBytes = 2_684_354_560L
            ),
            device = DeviceProfile(
                osApiLevel = 35,
                installFloor = 24,
                supportedAbis = listOf("arm64-v8a"),
                pageSizeBytes = 16384L
            ),
            expectedVerdict = Verdict.GREEN,
            expectedReason = TriageSignal.RUNNABLE_UNMODIFIED
        ),

        // Vector 14: Exceeds 2GB modified -> Exceeds repacking limit
        TriageVector(
            id = "vector_14_exceeds_2gb_modified",
            apk = ApkMetadata(
                targetSdk = 28,
                abis = emptyList(),
                usesApacheHttp = true,
                sizeBytes = 2_684_354_560L
            ),
            device = DeviceProfile(
                osApiLevel = 35,
                installFloor = 24,
                supportedAbis = listOf("arm64-v8a"),
                pageSizeBytes = 16384L
            ),
            expectedVerdict = Verdict.RED,
            expectedReason = TriageSignal.EXCEEDS_2GB_LIMIT_FOR_REPACKING
        ),

        // Vector 15: Self-signature check with modification -> Needs user input
        TriageVector(
            id = "vector_15_self_signature_check_with_modification",
            apk = ApkMetadata(
                targetSdk = 28,
                abis = emptyList(),
                usesApacheHttp = true,
                hasSelfSigCheck = true,
                sizeBytes = 15_000_000L
            ),
            device = DeviceProfile(
                osApiLevel = 35,
                installFloor = 24,
                supportedAbis = listOf("arm64-v8a"),
                pageSizeBytes = 16384L
            ),
            expectedVerdict = Verdict.NEEDS_USER_INPUT,
            expectedReason = TriageSignal.SIGNATURE_VERIFICATION_DETECTED
        ),

        // Vector 16: hasCode=false with shim -> Set hasCode true and lock 60Hz
        TriageVector(
            id = "vector_16_has_code_false_with_shim",
            apk = ApkMetadata(
                targetSdk = 22,
                abis = emptyList(),
                hasCode = false,
                hasFixedPhysics = true,
                sizeBytes = 10_000_000L
            ),
            device = DeviceProfile(
                osApiLevel = 35,
                installFloor = 24,
                supportedAbis = listOf("arm64-v8a"),
                pageSizeBytes = 16384L,
                isHighRefresh = true
            ),
            expectedVerdict = Verdict.YELLOW,
            expectedReason = TriageSignal.MODIFICATION_REQUIRED,
            expectedRequiredTransforms = listOf("SET_HAS_CODE_TRUE", "LOCK_60HZ_DISPLAY_MODE")
        )
    )

    @Test
    fun testAll16TriageVectors() {
        assertEquals("Must test exactly 16 vectors", 16, vectors.size)

        for (vec in vectors) {
            val result = TriageEvaluator.evaluateTriage(vec.apk, vec.device)

            assertEquals(
                "[${vec.id}] Verdict mismatch",
                vec.expectedVerdict,
                result.verdict
            )

            assertEquals(
                "[${vec.id}] Reason mismatch",
                vec.expectedReason,
                result.reason
            )

            if (vec.expectedInstallMethod != null) {
                assertEquals(
                    "[${vec.id}] Install method mismatch",
                    vec.expectedInstallMethod,
                    result.installMethod
                )
            }

            if (vec.expectedRequiredTransforms != null) {
                assertEquals(
                    "[${vec.id}] Required transforms mismatch",
                    vec.expectedRequiredTransforms.sorted(),
                    result.requiredTransforms.sorted()
                )
            }
        }
    }

    @Test
    fun testSplitApkUnsupported() {
        val apk = ApkMetadata(
            packageName = "com.example.split",
            targetSdk = 28,
            isSplitApk = true,
            sizeBytes = 5_000_000L
        )
        val device = DeviceProfile(osApiLevel = 35)
        val result = TriageEvaluator.evaluateTriage(apk, device)
        assertEquals(Verdict.RED, result.verdict)
        assertEquals(TriageSignal.SPLIT_APK_UNSUPPORTED, result.reason)
        assertEquals("Split APKs cannot be modernized independently. Modernize the base APK.", result.details)
        assertTrue(result.requiredTransforms.isEmpty())
    }

    @Test
    fun testApacheHttpTargetSdk29() {
        val apk = ApkMetadata(
            targetSdk = 29,
            usesApacheHttp = true,
            sizeBytes = 5_000_000L
        )
        val device = DeviceProfile(osApiLevel = 35)
        val result = TriageEvaluator.evaluateTriage(apk, device)
        assertEquals(Verdict.YELLOW, result.verdict)
        assertEquals(TriageSignal.MODIFICATION_REQUIRED, result.reason)
        assertEquals(listOf("INJECT_USES_LIBRARY_APACHE_HTTP"), result.requiredTransforms)
    }

    @Test
    fun testApacheHttpDeclaredNoInjection() {
        val apk = ApkMetadata(
            targetSdk = 28,
            usesApacheHttp = true,
            hasApacheLibraryDecl = true,
            sizeBytes = 5_000_000L
        )
        val device = DeviceProfile(osApiLevel = 35)
        val result = TriageEvaluator.evaluateTriage(apk, device)
        assertEquals(Verdict.GREEN, result.verdict)
        assertEquals(TriageSignal.RUNNABLE_UNMODIFIED, result.reason)
        assertTrue(result.requiredTransforms.isEmpty())
    }

    @Test
    fun testInvalidElfLayoutApi35PageSize() {
        val apk = ApkMetadata(
            targetSdk = 28,
            abis = listOf("arm64-v8a"),
            hasInvalidElfLayout = true,
            sizeBytes = 10_000_000L
        )
        val device = DeviceProfile(
            osApiLevel = 35,
            supportedAbis = listOf("arm64-v8a"),
            pageSizeBytes = 16384L
        )
        val result = TriageEvaluator.evaluateTriage(apk, device)
        assertEquals(Verdict.RED, result.verdict)
        assertEquals(TriageSignal.INCOMPATIBLE_PAGE_SIZE, result.reason)
        assertEquals("64-bit ELF has invalid or <16KB segment alignment on 16KB kernel (OS API=35 < 36)", result.details)
        assertTrue(result.requiredTransforms.isEmpty())
    }

    @Test
    fun testInvalidElfLayoutApi36PageSize() {
        val apk = ApkMetadata(
            targetSdk = 28,
            abis = listOf("arm64-v8a"),
            hasInvalidElfLayout = true,
            sizeBytes = 10_000_000L
        )
        val device = DeviceProfile(
            osApiLevel = 36,
            supportedAbis = listOf("arm64-v8a"),
            pageSizeBytes = 16384L
        )
        val result = TriageEvaluator.evaluateTriage(apk, device)
        assertEquals(Verdict.YELLOW, result.verdict)
        assertEquals(TriageSignal.MODIFICATION_REQUIRED, result.reason)
        assertEquals(listOf("PAGE_SIZE_COMPAT"), result.requiredTransforms)
    }

    @Test
    fun testCleartextOnApi28WithoutNsc() {
        val apk = ApkMetadata(
            targetSdk = 28,
            usesCleartextTraffic = null,
            hasNetworkSecurityConfig = false,
            sizeBytes = 5_000_000L
        )
        val device = DeviceProfile(osApiLevel = 28)
        val result = TriageEvaluator.evaluateTriage(apk, device)
        assertTrue(
            "Expected WARN_CLEARTEXT in warnings: ${result.warnings}",
            result.warnings.any { it.contains("WARN_CLEARTEXT: Cleartext HTTP traffic is blocked by default on Android 9+ (API 28+).") }
        )
    }

    @Test
    fun testCleartextDisabledExplicitly() {
        val apk = ApkMetadata(
            targetSdk = 28,
            usesCleartextTraffic = false,
            sizeBytes = 5_000_000L
        )
        val device = DeviceProfile(osApiLevel = 28)
        val result = TriageEvaluator.evaluateTriage(apk, device)
        assertTrue(
            "Expected WARN_CLEARTEXT when usesCleartextTraffic is false",
            result.warnings.any { it.contains("WARN_CLEARTEXT") }
        )
    }

    @Test
    fun testCleartextWithNetworkSecurityConfigSuppressesWarning() {
        val apk = ApkMetadata(
            targetSdk = 28,
            usesCleartextTraffic = null,
            hasNetworkSecurityConfig = true,
            sizeBytes = 5_000_000L
        )
        val device = DeviceProfile(osApiLevel = 28)
        val result = TriageEvaluator.evaluateTriage(apk, device)
        assertFalse(
            "WARN_CLEARTEXT should not be emitted when network security config is present",
            result.warnings.any { it.contains("WARN_CLEARTEXT") }
        )
    }

    @Test
    fun testLegacyTlsWarningEmitted() {
        val apk = ApkMetadata(
            targetSdk = 28,
            legacyTlsProtocols = listOf("TLSv1.1", "SSLv3"),
            sizeBytes = 5_000_000L
        )
        val device = DeviceProfile(osApiLevel = 35)
        val result = TriageEvaluator.evaluateTriage(apk, device)
        val tlsWarning = result.warnings.firstOrNull { it.contains("WARN_LEGACY_TLS") }
        assertNotNull("Expected WARN_LEGACY_TLS in warnings", tlsWarning)
        assertTrue(tlsWarning!!.contains("[SSLv3, TLSv1.1]"))
    }
}
