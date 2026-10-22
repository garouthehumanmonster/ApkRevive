package com.apkrevive.installer

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ShizukuConnectionStateTest {

    @Test
    fun testNotInstalledVariant() {
        val state: ShizukuConnectionState = ShizukuConnectionState.NotInstalled
        assertTrue(state is ShizukuConnectionState.NotInstalled)
    }

    @Test
    fun testServiceStoppedVariant() {
        val state: ShizukuConnectionState = ShizukuConnectionState.ServiceStopped
        assertTrue(state is ShizukuConnectionState.ServiceStopped)
    }

    @Test
    fun testPermissionDeniedVariant() {
        val stateWithRationale = ShizukuConnectionState.PermissionDenied(shouldShowRationale = true)
        assertTrue(stateWithRationale.shouldShowRationale)

        val stateWithoutRationale = ShizukuConnectionState.PermissionDenied(shouldShowRationale = false)
        assertFalse(stateWithoutRationale.shouldShowRationale)

        val defaultRationale = ShizukuConnectionState.PermissionDenied()
        assertFalse(defaultRationale.shouldShowRationale)
    }

    @Test
    fun testConnectedVariant() {
        val rootConnection = ShizukuConnectionState.Connected(
            uid = 0,
            isRootPrivilege = true,
            binderVersion = 13
        )
        assertEquals(0, rootConnection.uid)
        assertTrue(rootConnection.isRootPrivilege)
        assertEquals(13, rootConnection.binderVersion)

        val shellConnection = ShizukuConnectionState.Connected(
            uid = 2000,
            isRootPrivilege = false,
            binderVersion = 11
        )
        assertEquals(2000, shellConnection.uid)
        assertFalse(shellConnection.isRootPrivilege)
        assertEquals(11, shellConnection.binderVersion)
    }

    @Test
    fun testExhaustiveWhenHandling() {
        val states: List<ShizukuConnectionState> = listOf(
            ShizukuConnectionState.NotInstalled,
            ShizukuConnectionState.ServiceStopped,
            ShizukuConnectionState.PermissionDenied(false),
            ShizukuConnectionState.Connected(0, true, 13)
        )

        val labels = states.map { state ->
            when (state) {
                is ShizukuConnectionState.NotInstalled -> "NOT_INSTALLED"
                is ShizukuConnectionState.ServiceStopped -> "SERVICE_STOPPED"
                is ShizukuConnectionState.PermissionDenied -> "PERMISSION_DENIED"
                is ShizukuConnectionState.Connected -> "CONNECTED"
            }
        }

        assertEquals(
            listOf("NOT_INSTALLED", "SERVICE_STOPPED", "PERMISSION_DENIED", "CONNECTED"),
            labels
        )
    }

    @Test
    fun testInstallErrorParsing() {
        // -7 INSTALL_FAILED_UPDATE_INCOMPATIBLE
        val errIncompatible = ShizukuPackageInstallerBridge.parseInstallError(-7)
        assertEquals(-7, errIncompatible.errorCode)
        assertEquals("Existing app has a conflicting cryptographic signature.", errIncompatible.humanExplanation)
        assertEquals("Uninstall the existing version first or use the one-tap remediation to uninstall and retry.", errIncompatible.remediation)

        // String matching for signature mismatch
        val errStringIncompatible = ShizukuPackageInstallerBridge.parseInstallError(
            1,
            "INSTALL_FAILED_UPDATE_INCOMPATIBLE: Package signatures do not match"
        )
        assertEquals(-7, errStringIncompatible.errorCode)

        // -127 INSTALL_FAILED_DEPRECATED_SDK_VERSION
        val errDeprecated = ShizukuPackageInstallerBridge.parseInstallError(-127)
        assertEquals(-127, errDeprecated.errorCode)
        assertEquals("Target SDK below device floor.", errDeprecated.humanExplanation)
        assertEquals("Bypass flag will be used.", errDeprecated.remediation)

        // CPU ABI error (-16)
        val errAbi = ShizukuPackageInstallerBridge.parseInstallError(-16)
        assertEquals(-16, errAbi.errorCode)
        assertTrue(errAbi.humanExplanation.contains("processor architecture"))

        // Storage error (-4)
        val errStorage = ShizukuPackageInstallerBridge.parseInstallError(-4)
        assertEquals(-4, errStorage.errorCode)
        assertTrue(errStorage.humanExplanation.contains("storage is insufficient"))

        // Downgrade error (-25)
        val errDowngrade = ShizukuPackageInstallerBridge.parseInstallError(-25)
        assertEquals(-25, errDowngrade.errorCode)
        assertTrue(errDowngrade.humanExplanation.contains("older version"))

        // Unknown error fallback
        val errUnknown = ShizukuPackageInstallerBridge.parseInstallError(-999, "Custom internal error")
        assertEquals(-999, errUnknown.errorCode)
        assertEquals("Custom internal error", errUnknown.humanExplanation)
    }
}