package com.apkrevive

import com.apkrevive.core.ObbValidator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ObbValidatorTest {

    data class ObbVector(
        val id: String,
        val filename: String,
        val targetPackage: String,
        val apkVersionCode: Long,
        val expectedValid: Boolean,
        val expectedReasonSubstring: String? = null,
        val expectedWarningSubstring: String? = null
    )

    private val vectors = listOf(
        ObbVector(
            id = "OBB-VEC-01",
            filename = "main.100.com.example.game.obb",
            targetPackage = "com.example.game",
            apkVersionCode = 150L,
            expectedValid = true,
            expectedWarningSubstring = null
        ),
        ObbVector(
            id = "OBB-VEC-02",
            filename = "patch.100.com.example.game.obb",
            targetPackage = "com.example.game",
            apkVersionCode = 100L,
            expectedValid = true,
            expectedWarningSubstring = null
        ),
        ObbVector(
            id = "OBB-VEC-03",
            filename = "main.100.com.example.game.obb\n",
            targetPackage = "com.example.game",
            apkVersionCode = 150L,
            expectedValid = false,
            expectedReasonSubstring = "INVALID_OBB_FILENAME_FORMAT"
        ),
        ObbVector(
            id = "OBB-VEC-04",
            filename = "../../data/app/evil.obb",
            targetPackage = "com.example.game",
            apkVersionCode = 100L,
            expectedValid = false,
            expectedReasonSubstring = "PATH_TRAVERSAL_DETECTED"
        ),
        ObbVector(
            id = "OBB-VEC-05",
            filename = "main.100.com.other.game.obb",
            targetPackage = "com.example.game",
            apkVersionCode = 150L,
            expectedValid = false,
            expectedReasonSubstring = "PACKAGE_NAME_MISMATCH"
        ),
        ObbVector(
            id = "OBB-VEC-06",
            filename = "main.200.com.example.game.obb",
            targetPackage = "com.example.game",
            apkVersionCode = 100L,
            expectedValid = true,
            expectedWarningSubstring = "EXPANSION_VERSION_AHEAD_OF_APK"
        )
    )

    @Test
    fun testAll6ObbVectors() {
        for (vec in vectors) {
            val res = ObbValidator.validateObbDelivery(
                obbFilename = vec.filename,
                targetPackage = vec.targetPackage,
                currentApkVersion = vec.apkVersionCode
            )

            assertEquals("[${vec.id}] validity mismatch", vec.expectedValid, res.isValid)

            if (vec.expectedReasonSubstring != null) {
                assertNotNull("[${vec.id}] expected reason but got null", res.reason)
                assertTrue(
                    "[${vec.id}] reason '${res.reason}' does not contain '${vec.expectedReasonSubstring}'",
                    res.reason!!.contains(vec.expectedReasonSubstring)
                )
            }

            if (vec.expectedWarningSubstring != null) {
                assertNotNull("[${vec.id}] expected warning but got null", res.warning)
                assertTrue(
                    "[${vec.id}] warning '${res.warning}' does not contain '${vec.expectedWarningSubstring}'",
                    res.warning!!.contains(vec.expectedWarningSubstring)
                )
            } else if (vec.expectedValid) {
                assertNull("[${vec.id}] expected no warning but got '${res.warning}'", res.warning)
            }
        }
    }

    @Test
    fun testPathTraversalGuards() {
        // Null byte
        val nullByteResult = ObbValidator.validateObbDelivery(
            "main.1.com.pkg.obb\u0000",
            "com.pkg",
            1L
        )
        assertFalse(nullByteResult.isValid)
        assertEquals("PATH_TRAVERSAL_DETECTED", nullByteResult.reason)

        // Forward slash
        val forwardSlashResult = ObbValidator.validateObbDelivery(
            "sub/main.1.com.pkg.obb",
            "com.pkg",
            1L
        )
        assertFalse(forwardSlashResult.isValid)
        assertEquals("PATH_TRAVERSAL_DETECTED", forwardSlashResult.reason)

        // Backward slash
        val backSlashResult = ObbValidator.validateObbDelivery(
            "sub\\main.1.com.pkg.obb",
            "com.pkg",
            1L
        )
        assertFalse(backSlashResult.isValid)
        assertEquals("PATH_TRAVERSAL_DETECTED", backSlashResult.reason)

        // Relative parent ..
        val parentDirResult = ObbValidator.validateObbDelivery(
            "../main.1.com.pkg.obb",
            "com.pkg",
            1L
        )
        assertFalse(parentDirResult.isValid)
        assertEquals("PATH_TRAVERSAL_DETECTED", parentDirResult.reason)
    }

    @Test
    fun testObbDestinationPathAndType() {
        val res = ObbValidator.validateObbDelivery(
            "main.123.com.example.game.obb",
            "com.example.game",
            200L
        )
        assertTrue(res.isValid)
        assertEquals("main", res.obbType)
        assertEquals(123L, res.obbVersion)
        assertEquals("/Android/obb/com.example.game/main.123.com.example.game.obb", res.destinationPath)
        assertNull(res.warning)

        val patchRes = ObbValidator.validateObbDelivery(
            "patch.123.com.example.game.obb",
            "com.example.game",
            200L
        )
        assertTrue(patchRes.isValid)
        assertEquals("patch", patchRes.obbType)
        assertEquals(123L, patchRes.obbVersion)
        assertEquals("/Android/obb/com.example.game/patch.123.com.example.game.obb", patchRes.destinationPath)
    }
}
