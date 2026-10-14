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
    private val OBB_REGEX = Regex("^(main|patch)\\.([0-9]+)\\.([a-zA-Z0-9_]+(?:\\.[a-zA-Z0-9_]+)+)\\.obb$")

    fun validateObbDelivery(
        obbFilename: String,
        targetPackage: String,
        currentApkVersion: Long
    ): ObbValidationResult {
        if (obbFilename.contains('\u0000') ||
            obbFilename.contains('/') ||
            obbFilename.contains('\\') ||
            obbFilename.contains("..")
        ) {
            return ObbValidationResult(
                isValid = false,
                reason = "PATH_TRAVERSAL_DETECTED"
            )
        }

        if (obbFilename.endsWith('\n') || obbFilename.endsWith('\r')) {
            return ObbValidationResult(
                isValid = false,
                reason = "INVALID_OBB_FILENAME_FORMAT (Trailing newline rejected by fullmatch)"
            )
        }

        val match = OBB_REGEX.matchEntire(obbFilename)
        if (match == null) {
            return ObbValidationResult(
                isValid = false,
                reason = "INVALID_OBB_FILENAME_FORMAT (Filename does not match expected scheme)"
            )
        }

        val (obbType, obbVersionStr, obbPkg) = match.destructured
        val obbVersion = obbVersionStr.toLongOrNull() ?: 0L

        if (obbPkg != targetPackage) {
            return ObbValidationResult(
                isValid = false,
                reason = "PACKAGE_NAME_MISMATCH",
                details = "OBB package '$obbPkg' != '$targetPackage'"
            )
        }

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
