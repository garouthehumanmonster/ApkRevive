package com.apkrevive.core

data class ObbValidationResult(
    val isValid: Boolean,
    val reason: String? = null,
    val details: String? = null,
    val obbType: String? = null,
    val obbVersion: Long? = null,
    val destinationPath: String? = null,
    val warning: String? = null
)

object ObbValidator {
    // Package name allowlist: ^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+$
    val PACKAGE_ALLOWLIST = Regex("^[A-Za-z_][A-Za-z0-9_]*(\\.[A-Za-z_][A-Za-z0-9_]*)+$")

    // General OBB scheme regex
    private val GENERIC_OBB_REGEX = Regex("^(main|patch)\\.([0-9]+)\\.([A-Za-z_][A-Za-z0-9_]*(?:\\.[A-Za-z_][A-Za-z0-9_]*)+)\\.obb$")

    // Dangerous shell metacharacters rejected unconditionally
    private val HOSTILE_CHARS = setOf('\'', '"', ';', '$', '`', '&', '|', '<', '>', '(', ')', '{', '}', '*', '?', '[', ']', ' ', '\t', '\n', '\r', '\u0000')

    fun getObbFilenameRegex(targetPackage: String): Regex {
        val escapedPkg = Regex.escape(targetPackage)
        return Regex("^(main|patch)\\.([0-9]+)\\.$escapedPkg\\.obb$")
    }

    /**
     * Resolves the target directory for an app's OBB expansion files.
     *
     * UserId 0 is standard for the primary device user. Non-zero user IDs (e.g. work profiles,
     * secondary accounts) point to `/storage/emulated/$userId/Android/obb/$targetPackage`.
     * Note that shell UID 2000 access depends on whether user storage is unlocked and mounted.
     */
    fun resolveObbDirectory(targetPackage: String, userId: Int = 0): String {
        require(userId >= 0) { "userId must be non-negative: $userId" }
        return "/storage/emulated/$userId/Android/obb/$targetPackage"
    }

    /**
     * Resolves the full destination file path for an app's OBB expansion file on device storage.
     *
     * UserId 0 is standard for the primary device user. Non-zero user IDs (e.g. work profiles,
     * secondary accounts) point to `/storage/emulated/$userId/Android/obb/$targetPackage/$obbFilename`.
     * Note that shell UID 2000 access depends on whether user storage is unlocked and mounted.
     */
    fun resolveObbDestinationPath(targetPackage: String, obbFilename: String, userId: Int = 0): String {
        require(userId >= 0) { "userId must be non-negative: $userId" }
        return "${resolveObbDirectory(targetPackage, userId)}/$obbFilename"
    }

    /**
     * Validates an incoming OBB delivery candidate against strict filename, path traversal,
     * package allowlist, shell safety, and APK version constraints.
     *
     * UserId 0 is standard for the primary device user. Non-zero user IDs (e.g. work profiles,
     * secondary accounts) point to `/storage/emulated/$userId/Android/obb/$targetPackage/$obbFilename`.
     * Note that shell UID 2000 access depends on whether user storage is unlocked and mounted.
     */
    fun validateObbDelivery(
        obbFilename: String,
        targetPackage: String,
        currentApkVersion: Long,
        userId: Int = 0
    ): ObbValidationResult {
        require(userId >= 0) { "userId must be non-negative: $userId" }

        // 1. Path traversal checks
        if (obbFilename.contains('\u0000') ||
            obbFilename.contains('/') ||
            obbFilename.contains('\\') ||
            obbFilename.contains("..") ||
            targetPackage.contains("..") ||
            targetPackage.contains('/') ||
            targetPackage.contains('\\')
        ) {
            return ObbValidationResult(
                isValid = false,
                reason = "PATH_TRAVERSAL_DETECTED"
            )
        }

        // 2. Shell metacharacter / hostile input checks
        if (obbFilename.any { it in HOSTILE_CHARS } || targetPackage.any { it in HOSTILE_CHARS }) {
            return ObbValidationResult(
                isValid = false,
                reason = "HOSTILE_INPUT_DETECTED (INVALID_OBB_FILENAME_FORMAT)",
                details = "Forbidden shell metacharacters, spaces, or control characters detected"
            )
        }

        // 3. ASCII purity check (reject unicode / homoglyphs)
        if (!obbFilename.all { it.code in 32..126 } || !targetPackage.all { it.code in 32..126 }) {
            return ObbValidationResult(
                isValid = false,
                reason = "HOSTILE_INPUT_DETECTED (INVALID_OBB_FILENAME_FORMAT)",
                details = "Non-ASCII / Unicode characters rejected"
            )
        }

        // 4. Strict package allowlist validation
        if (!PACKAGE_ALLOWLIST.matches(targetPackage)) {
            return ObbValidationResult(
                isValid = false,
                reason = "INVALID_PACKAGE_NAME",
                details = "Package name does not match strict allowlist: $targetPackage"
            )
        }

        // 5. Strict filename allowlist validation anchored to targetPackage
        val packageObbRegex = getObbFilenameRegex(targetPackage)
        val match = packageObbRegex.matchEntire(obbFilename)
        if (match == null) {
            // Check if generic OBB format matches but package differs
            val genericMatch = GENERIC_OBB_REGEX.matchEntire(obbFilename)
            if (genericMatch != null) {
                val (_, _, obbPkg) = genericMatch.destructured
                return ObbValidationResult(
                    isValid = false,
                    reason = "PACKAGE_NAME_MISMATCH",
                    details = "OBB package '$obbPkg' != '$targetPackage'"
                )
            }
            return ObbValidationResult(
                isValid = false,
                reason = "INVALID_OBB_FILENAME_FORMAT",
                details = "Filename does not match expected pattern ^(main|patch).[0-9]+.<targetPackage>.obb$"
            )
        }

        val (obbType, obbVersionStr) = match.destructured
        val obbVersion = obbVersionStr.toLongOrNull() ?: 0L

        val warning = if (obbVersion > currentApkVersion) {
            "EXPANSION_VERSION_AHEAD_OF_APK ($obbVersion > $currentApkVersion)"
        } else {
            null
        }

        val destPath = "/Android/obb/$targetPackage/$obbFilename"
        return ObbValidationResult(
            isValid = true,
            obbType = obbType,
            obbVersion = obbVersion,
            destinationPath = destPath,
            warning = warning
        )
    }
}
