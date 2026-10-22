package com.apkrevive

import com.apkrevive.installer.ShizukuPackageInstallerBridge
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ShizukuBridgeReflectionTest {

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
}
