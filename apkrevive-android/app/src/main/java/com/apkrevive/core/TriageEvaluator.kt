package com.apkrevive.core

object TriageEvaluator {

    val BIONIC_GREYLIST = setOf(
        "libandroid_runtime.so",
        "libcutils.so",
        "libcrypto.so",
        "libssl.so"
    )

    val PUBLIC_SYSTEM_LIBRARIES = setOf(
        "libc.so", "libm.so", "libdl.so", "liblog.so", "libz.so",
        "libandroid.so", "libjnigraphics.so", "libEGL.so", "libGLESv1_CM.so",
        "libGLESv2.so", "libGLESv3.so", "libOpenSLES.so", "libOpenMAXAL.so",
        "libvulkan.so", "libmediandk.so", "libaaudio.so"
    )

    fun evaluateTriage(apkMeta: ApkMetadata, deviceProfile: DeviceProfile): TriageResult {
        val targetSdk = apkMeta.targetSdk
        val apkAbis = apkMeta.abis.toSet()
        val elfLoadAlign = apkMeta.elfLoadAlign64bit
        val privateLibs = apkMeta.privateLibs
        val usesApacheHttp = apkMeta.usesApacheHttp
        val hasCode = apkMeta.hasCode
        val isNonResizeable = apkMeta.isNonResizeable
        val hasFixedPhysics = apkMeta.hasFixedPhysics
        val hasSelfSigCheck = apkMeta.hasSelfSigCheck
        val hasDrm = apkMeta.hasDrm
        val apkSize = apkMeta.sizeBytes

        val deviceSdk = deviceProfile.osApiLevel
        val deviceFloor = deviceProfile.installFloor
        val deviceAbis = deviceProfile.supportedAbis.toSet()
        val devicePageSize = deviceProfile.pageSizeBytes
        val deviceIsWidescreen = deviceProfile.isWidescreen
        val deviceIsHighRefresh = deviceProfile.isHighRefresh

        val warnings = mutableListOf<String>()
        val requiredTransforms = mutableListOf<String>()

        // 0. Split APK Check
        if (apkMeta.isSplitApk) {
            return TriageResult(
                verdict = Verdict.RED,
                reason = TriageSignal.SPLIT_APK_UNSUPPORTED,
                details = "Split APKs cannot be modernized independently. Modernize the base APK.",
                warnings = warnings,
                requiredTransforms = emptyList()
            )
        }

        // 1. Device ABI Check
        if (apkAbis.isNotEmpty()) {
            val matchingAbis = apkAbis.intersect(deviceAbis)
            if (matchingAbis.isEmpty()) {
                return TriageResult(
                    verdict = Verdict.RED,
                    reason = TriageSignal.INCOMPATIBLE_DEVICE_ABI,
                    details = "APK ABIs ${apkMeta.abis.sorted()} do not match device ABIs ${deviceProfile.supportedAbis.sorted()}",
                    warnings = warnings,
                    requiredTransforms = emptyList()
                )
            }
        }

        // 2. Private System Libraries & Bionic Greylist Check
        if (privateLibs.isNotEmpty()) {
            val blockedLibs = mutableListOf<String>()
            for (lib in privateLibs) {
                if (lib in PUBLIC_SYSTEM_LIBRARIES) {
                    continue
                }
                if (targetSdk < 24 && lib in BIONIC_GREYLIST) {
                    continue
                }
                blockedLibs.add(lib)
            }

            if (blockedLibs.isNotEmpty()) {
                return TriageResult(
                    verdict = Verdict.RED,
                    reason = TriageSignal.UNRESOLVABLE_SYSTEM_LIBRARY,
                    details = "Blocked private platform libraries: $blockedLibs (targetSdk=$targetSdk)",
                    warnings = warnings,
                    requiredTransforms = emptyList()
                )
            }
        }

        // 3. 16KB Page Size Segment Alignment Check
        val has64BitNative = apkAbis.intersect(setOf("arm64-v8a", "x86_64")).isNotEmpty()
        if (devicePageSize == 16384L && has64BitNative) {
            if ((elfLoadAlign != null && elfLoadAlign < 16384L) || apkMeta.hasInvalidElfLayout) {
                if (deviceSdk < 36) {
                    return TriageResult(
                        verdict = Verdict.RED,
                        reason = TriageSignal.INCOMPATIBLE_PAGE_SIZE,
                        details = "64-bit ELF has invalid or <16KB segment alignment on 16KB kernel (OS API=$deviceSdk < 36)",
                        warnings = warnings,
                        requiredTransforms = emptyList()
                    )
                } else {
                    requiredTransforms.add("PAGE_SIZE_COMPAT")
                }
            }
        }

        // 4. Modification Requirements Analysis
        if (targetSdk >= 28 && usesApacheHttp && !apkMeta.hasApacheLibraryDecl) {
            requiredTransforms.add("INJECT_USES_LIBRARY_APACHE_HTTP")
        }

        if (!hasCode && ("PAGE_SIZE_COMPAT" in requiredTransforms || hasFixedPhysics || isNonResizeable)) {
            requiredTransforms.add("SET_HAS_CODE_TRUE")
        }

        if (isNonResizeable && deviceIsWidescreen) {
            requiredTransforms.add("EXPAND_ASPECT_RATIO")
        }

        if (hasFixedPhysics && deviceIsHighRefresh) {
            requiredTransforms.add("LOCK_60HZ_DISPLAY_MODE")
        }

        if (targetSdk >= 28 && deviceSdk >= 28 && (apkMeta.usesCleartextTraffic == false || (apkMeta.usesCleartextTraffic == null && !apkMeta.hasNetworkSecurityConfig))) {
            warnings.add("WARN_CLEARTEXT: Cleartext HTTP traffic is blocked by default on Android 9+ (API 28+).")
        }

        if (apkMeta.legacyTlsProtocols.isNotEmpty()) {
            warnings.add("WARN_LEGACY_TLS: Deprecated TLS protocol references (${apkMeta.legacyTlsProtocols.sorted()}) detected.")
        }

        if (hasDrm) {
            warnings.add("DRM_DETECTED (Informational: unmodified install will not bypass license)")
        }
        if (apkMeta.staticRemovedApis.isNotEmpty()) {
            warnings.add("STATIC_REMOVED_APIS_REFERENCED: ${apkMeta.staticRemovedApis}")
        }

        // 5. Evaluate Verdict Class
        if (requiredTransforms.isNotEmpty()) {
            if (apkSize > 2L * 1024L * 1024L * 1024L) {
                return TriageResult(
                    verdict = Verdict.RED,
                    reason = TriageSignal.EXCEEDS_2GB_LIMIT_FOR_REPACKING,
                    details = "Archive size $apkSize exceeds 2GB container repacker limit",
                    warnings = warnings,
                    requiredTransforms = requiredTransforms
                )
            }

            if (hasSelfSigCheck) {
                return TriageResult(
                    verdict = Verdict.NEEDS_USER_INPUT,
                    reason = TriageSignal.SIGNATURE_VERIFICATION_DETECTED,
                    details = "APK contains self-signature checks; re-signing will alter signature fingerprint",
                    warnings = warnings,
                    requiredTransforms = requiredTransforms
                )
            }

            return TriageResult(
                verdict = Verdict.YELLOW,
                reason = TriageSignal.MODIFICATION_REQUIRED,
                details = "Requires transforms: $requiredTransforms",
                warnings = warnings,
                requiredTransforms = requiredTransforms
            )
        }

        // 6. Unmodified Path (Green)
        val installMethod = if (targetSdk >= deviceFloor) {
            "DIRECT_INSTALL"
        } else {
            "BYPASS_LOW_TARGET_SDK_BLOCK"
        }

        return TriageResult(
            verdict = Verdict.GREEN,
            reason = TriageSignal.RUNNABLE_UNMODIFIED,
            installMethod = installMethod,
            details = "No transforms needed. Install method: $installMethod (targetSdk=$targetSdk, floor=$deviceFloor)",
            warnings = warnings,
            requiredTransforms = emptyList()
        )
    }
}
