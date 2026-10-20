package com.apkrevive

import com.apkrevive.core.ObbValidator
import com.apkrevive.installer.ShizukuPackageInstallerBridge
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class ShizukuBridgeReflectionTest {

    @After
    fun tearDown() {
        ShizukuPackageInstallerBridge.newProcessMethodResolver = null
        ShizukuPackageInstallerBridge.installExecutor = null
        ShizukuPackageInstallerBridge.uninstallExecutor = null
    }

    // Test fake mimicking PackageInstaller.SessionParams field layout
    class FakeSessionParams {
        @JvmField
        var installFlags: Int = 0
    }

    open class SuperSessionParams {
        @JvmField
        var installFlags: Int = 0x00000004
    }

    class SubSessionParams : SuperSessionParams()

    class ParamsWithoutInstallFlags {
        @JvmField
        var mode: Int = 1
    }

    @Test
    fun testIsBypassLowTargetSdkSupported() {
        assertFalse(ShizukuPackageInstallerBridge.isBypassLowTargetSdkSupported(33))
        assertTrue(ShizukuPackageInstallerBridge.isBypassLowTargetSdkSupported(34))
        assertTrue(ShizukuPackageInstallerBridge.isBypassLowTargetSdkSupported(35))
        assertTrue(ShizukuPackageInstallerBridge.isBypassLowTargetSdkSupported(36))
    }

    @Test
    fun testInstallExecutorHook() = kotlinx.coroutines.runBlocking {
        var called = false
        ShizukuPackageInstallerBridge.installExecutor = { _, _, bypass ->
            called = true
            assertTrue(bypass)
            Result.success(42)
        }
        try {
            val fakeStream = java.io.ByteArrayInputStream(byteArrayOf(1, 2, 3))
            val result = ShizukuPackageInstallerBridge.installApk(
                context = android.content.ContextWrapper(null),
                apkStream = fakeStream,
                apkSize = 3L,
                bypassLowTargetSdk = true
            )
            assertTrue(called)
            assertTrue(result.isSuccess)
            assertEquals(42, result.getOrNull())
        } finally {
            ShizukuPackageInstallerBridge.installExecutor = null
        }
    }

    @Test
    fun testApplyBypassGuardsOldSdkInt() {
        val fake = FakeSessionParams()
        // API 33 does not have INSTALL_BYPASS_LOW_TARGET_SDK_BLOCK in PackageManager
        val success = ShizukuPackageInstallerBridge.applyBypassLowTargetSdkFlag(fake, sdkInt = 33)
        assertFalse("Should return false on API 33 when flag unsupported", success)
        assertEquals(0, fake.installFlags)

        val success34 = ShizukuPackageInstallerBridge.applyBypassLowTargetSdkFlag(fake, sdkInt = 34)
        assertTrue("Should return true on API 34", success34)
        assertEquals(0x01000000, fake.installFlags)
    }

    @Test
    fun testApplyBypassLowTargetSdkFlagSetsBitwiseFlag() {
        val fake = FakeSessionParams()
        assertEquals(0, fake.installFlags)

        val success = ShizukuPackageInstallerBridge.applyBypassLowTargetSdkFlag(fake)
        assertTrue("applyBypassLowTargetSdkFlag should return true", success)

        val expectedFlag = ShizukuPackageInstallerBridge.INSTALL_BYPASS_LOW_TARGET_SDK_BLOCK
        assertEquals(0x01000000, expectedFlag)
        assertEquals(expectedFlag, fake.installFlags)
        assertTrue(
            "INSTALL_BYPASS_LOW_TARGET_SDK_BLOCK (0x01000000) bit must be set",
            (fake.installFlags and expectedFlag) == expectedFlag
        )
    }

    @Test
    fun testApplyBypassPreservesExistingFlags() {
        val fake = FakeSessionParams()
        val initialFlags = 0x00000002 // e.g. INSTALL_REPLACE_EXISTING
        fake.installFlags = initialFlags

        val success = ShizukuPackageInstallerBridge.applyBypassLowTargetSdkFlag(fake)
        assertTrue(success)

        val expected = initialFlags or ShizukuPackageInstallerBridge.INSTALL_BYPASS_LOW_TARGET_SDK_BLOCK
        assertEquals(expected, fake.installFlags)
        assertEquals(0x01000002, fake.installFlags)
    }

    @Test
    fun testApplyBypassIdempotence() {
        val fake = FakeSessionParams()
        ShizukuPackageInstallerBridge.applyBypassLowTargetSdkFlag(fake)
        val firstResult = fake.installFlags

        // Second call should not corrupt the bitmask
        ShizukuPackageInstallerBridge.applyBypassLowTargetSdkFlag(fake)
        assertEquals(firstResult, fake.installFlags)
        assertEquals(0x01000000, fake.installFlags)
    }

    @Test
    fun testApplyBypassResolvesSuperclassField() {
        val sub = SubSessionParams()
        assertEquals(0x00000004, sub.installFlags)

        val success = ShizukuPackageInstallerBridge.applyBypassLowTargetSdkFlag(sub)
        assertTrue("Superclass installFlags field should be resolved", success)
        assertEquals(0x01000004, sub.installFlags)
    }

    @Test
    fun testApplyBypassReturnsFalseForMissingField() {
        val noField = ParamsWithoutInstallFlags()
        val success = ShizukuPackageInstallerBridge.applyBypassLowTargetSdkFlag(noField)
        assertFalse("Should return false when installFlags field is absent", success)
    }

    @Test
    fun testInstallApkViaShellWithoutPermissionFails() = kotlinx.coroutines.runBlocking {
        val stream = java.io.ByteArrayInputStream(byteArrayOf(1, 2, 3))
        val result = ShizukuPackageInstallerBridge.installApkViaShell(
            apkStream = stream,
            apkSize = 3L,
            bypassLowTargetSdk = true
        )
        assertFalse("Shell install must fail when Shizuku permission is not granted", result.isSuccess)
        val ex = result.exceptionOrNull()
        assertTrue(ex is IllegalStateException)
        assertTrue(ex?.message?.contains("Shizuku") == true)
    }

    @Test
    fun testPushObbViaShellInvalidFilenameFails() = kotlinx.coroutines.runBlocking {
        val stream = java.io.ByteArrayInputStream(byteArrayOf(1, 2, 3))
        val result = ShizukuPackageInstallerBridge.pushObbViaShell(
            obbStream = stream,
            targetPackage = "com.example.game",
            obbFilename = "../../evil.obb",
            expectedSize = 100L,
            currentApkVersion = 100L
        )
        assertFalse("OBB push must reject traversal filenames before attempting execution", result.isSuccess)
        val ex = result.exceptionOrNull()
        assertTrue(ex is IllegalArgumentException)
        assertTrue(ex?.message?.contains("PATH_TRAVERSAL_DETECTED") == true)
    }

    @Test
    fun testPushObbViaShellWithoutPermissionFails() = kotlinx.coroutines.runBlocking {
        val stream = java.io.ByteArrayInputStream(byteArrayOf(1, 2, 3))
        val result = ShizukuPackageInstallerBridge.pushObbViaShell(
            obbStream = stream,
            targetPackage = "com.example.game",
            obbFilename = "main.100.com.example.game.obb",
            expectedSize = 100L,
            currentApkVersion = 100L
        )
        assertFalse("OBB push must fail if Shizuku permission not granted", result.isSuccess)
        val ex = result.exceptionOrNull()
        assertTrue(ex is IllegalStateException)
        assertTrue(ex?.message?.contains("Shizuku") == true)
    }

    @Test
    fun testPushObbViaShellFailsIfExpectedSizeNonPositive() = kotlinx.coroutines.runBlocking {
        val stream = java.io.ByteArrayInputStream(byteArrayOf(1, 2, 3))
        val resultZero = ShizukuPackageInstallerBridge.pushObbViaShell(
            obbStream = stream,
            targetPackage = "com.example.game",
            obbFilename = "main.100.com.example.game.obb",
            expectedSize = 0L,
            currentApkVersion = 100L
        )
        assertFalse("expectedSize=0 must fail", resultZero.isSuccess)
        assertTrue(resultZero.exceptionOrNull() is IllegalArgumentException)

        val stream2 = java.io.ByteArrayInputStream(byteArrayOf(1, 2, 3))
        val resultNegative = ShizukuPackageInstallerBridge.pushObbViaShell(
            obbStream = stream2,
            targetPackage = "com.example.game",
            obbFilename = "main.100.com.example.game.obb",
            expectedSize = -5L,
            currentApkVersion = 100L
        )
        assertFalse("expectedSize<0 must fail", resultNegative.isSuccess)
        assertTrue(resultNegative.exceptionOrNull() is IllegalArgumentException)
    }

    // Hostile input validation tests for ObbValidator.validateObbDelivery
    @Test
    fun testHostileInputRejectsQuotes() {
        val res = ObbValidator.validateObbDelivery("main.100.com.example'app.obb", "com.example.app", 100L)
        assertFalse(res.isValid)
        assertTrue(res.reason?.contains("HOSTILE_INPUT_DETECTED") == true)
    }

    @Test
    fun testHostileInputRejectsSemicolons() {
        val res = ObbValidator.validateObbDelivery("main.100.com.example;rm.obb", "com.example.app", 100L)
        assertFalse(res.isValid)
        assertTrue(res.reason?.contains("HOSTILE_INPUT_DETECTED") == true)
    }

    @Test
    fun testHostileInputRejectsCommandSubstitutionDollar() {
        val res = ObbValidator.validateObbDelivery("main.100.$(whoami).obb", "com.example.app", 100L)
        assertFalse(res.isValid)
        assertTrue(res.reason?.contains("HOSTILE_INPUT_DETECTED") == true)
    }

    @Test
    fun testHostileInputRejectsCommandSubstitutionBackticks() {
        val res = ObbValidator.validateObbDelivery("main.100.`id`.obb", "com.example.app", 100L)
        assertFalse(res.isValid)
        assertTrue(res.reason?.contains("HOSTILE_INPUT_DETECTED") == true)
    }

    @Test
    fun testHostileInputRejectsNewlines() {
        val res = ObbValidator.validateObbDelivery("main.100.com.example\napp.obb", "com.example.app", 100L)
        assertFalse(res.isValid)
        assertTrue(res.reason?.contains("HOSTILE_INPUT_DETECTED") == true)
    }

    @Test
    fun testHostileInputRejectsSpaces() {
        val res = ObbValidator.validateObbDelivery("main.100.com.example app.obb", "com.example.app", 100L)
        assertFalse(res.isValid)
        assertTrue(res.reason?.contains("HOSTILE_INPUT_DETECTED") == true)
    }

    @Test
    fun testHostileInputRejectsDirectoryTraversalRelative() {
        val res = ObbValidator.validateObbDelivery("../main.100.com.example.obb", "com.example", 100L)
        assertFalse(res.isValid)
        assertEquals("PATH_TRAVERSAL_DETECTED", res.reason)
    }

    @Test
    fun testHostileInputRejectsDirectoryTraversalSlashInFilename() {
        val res = ObbValidator.validateObbDelivery("main.100/com.example.obb", "com.example", 100L)
        assertFalse(res.isValid)
        assertEquals("PATH_TRAVERSAL_DETECTED", res.reason)
    }

    @Test
    fun testHostileInputRejectsAbsolutePaths() {
        val res = ObbValidator.validateObbDelivery("/storage/emulated/0/main.100.com.example.obb", "com.example", 100L)
        assertFalse(res.isValid)
        assertEquals("PATH_TRAVERSAL_DETECTED", res.reason)
    }

    @Test
    fun testHostileInputRejectsUnicodeHomoglyphs() {
        // Cyrillic small letter 'a' (U+0430) instead of ASCII 'a'
        val res = ObbValidator.validateObbDelivery("main.100.com.ex\u0430mple.obb", "com.example", 100L)
        assertFalse(res.isValid)
        assertTrue(res.reason?.contains("HOSTILE_INPUT_DETECTED") == true)
    }

    @Test
    fun testValidPackageAllowlist() {
        assertTrue(ObbValidator.PACKAGE_ALLOWLIST.matches("com.example.app"))
        assertTrue(ObbValidator.PACKAGE_ALLOWLIST.matches("a.b.c_d"))
    }

    @Test
    fun testInvalidPackageAllowlist() {
        assertFalse(ObbValidator.PACKAGE_ALLOWLIST.matches("123bad"))
        assertFalse(ObbValidator.PACKAGE_ALLOWLIST.matches("com..bad"))
        assertFalse(ObbValidator.PACKAGE_ALLOWLIST.matches("com.bad-name"))
    }

    @Test
    fun testMultiUserPathResolution() {
        val path = ObbValidator.resolveObbDestinationPath(
            targetPackage = "com.example.app",
            obbFilename = "main.100.com.example.app.obb",
            userId = 10
        )
        assertEquals("/storage/emulated/10/Android/obb/com.example.app/main.100.com.example.app.obb", path)

        val dir = ObbValidator.resolveObbDirectory("com.example.app", userId = 10)
        assertEquals("/storage/emulated/10/Android/obb/com.example.app", dir)
    }

    @Test(expected = IllegalArgumentException::class)
    fun testNegativeUserIdThrowsInResolveDestinationPath() {
        ObbValidator.resolveObbDestinationPath("com.example.app", "main.100.com.example.app.obb", -1)
    }

    @Test(expected = IllegalArgumentException::class)
    fun testNegativeUserIdThrowsInResolveDirectory() {
        ObbValidator.resolveObbDirectory("com.example.app", -1)
    }

    @Test(expected = IllegalArgumentException::class)
    fun testNegativeUserIdThrowsInValidateDelivery() {
        ObbValidator.validateObbDelivery("main.100.com.example.app.obb", "com.example.app", 100L, -1)
    }

    // Shizuku reflection unit tests
    @Test
    fun testInvokeShizukuNewProcessMissingMethodThrowsIllegalStateException() {
        try {
            ShizukuPackageInstallerBridge.newProcessMethodResolver = {
                throw NoSuchMethodException("newProcess")
            }
            ShizukuPackageInstallerBridge.invokeShizukuNewProcess(arrayOf("echo", "test"))
            fail("Expected IllegalStateException when newProcess is missing")
        } catch (e: IllegalStateException) {
            assertTrue(
                "Exception message should mention unavailable newProcess: ${e.message}",
                e.message?.contains("Shizuku.newProcess is unavailable") == true
            )
            assertTrue(e.cause is NoSuchMethodException)
        } finally {
            ShizukuPackageInstallerBridge.newProcessMethodResolver = null
        }
    }

    // Error code matching tests
    @Test
    fun testParseInstallErrorMatchesDeprecatedSdkVersionByName() {
        val explanation = ShizukuPackageInstallerBridge.parseInstallError(
            errorCode = 1,
            rawMessage = "Installation failed: INSTALL_FAILED_DEPRECATED_SDK_VERSION"
        )
        assertEquals(
            ShizukuPackageInstallerBridge.INSTALL_FAILED_DEPRECATED_SDK_VERSION,
            explanation.errorCode
        )
        assertTrue(
            "Remediation must mention 'Shizuku bypass flag required': ${explanation.remediation}",
            explanation.remediation.contains("Shizuku bypass flag required")
        )
    }

    @Test
    fun testParseInstallErrorMatchesDeprecatedSdkVersionByErrorCode() {
        val explanation = ShizukuPackageInstallerBridge.parseInstallError(
            errorCode = ShizukuPackageInstallerBridge.INSTALL_FAILED_DEPRECATED_SDK_VERSION,
            rawMessage = "Arbitrary failure"
        )
        assertEquals(
            ShizukuPackageInstallerBridge.INSTALL_FAILED_DEPRECATED_SDK_VERSION,
            explanation.errorCode
        )
        assertTrue(
            explanation.remediation.contains("Shizuku bypass flag required")
        )
    }
}
