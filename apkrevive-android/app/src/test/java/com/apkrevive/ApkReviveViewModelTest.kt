package com.apkrevive

import com.apkrevive.core.ApkMetadata
import com.apkrevive.core.DeviceProfile
import com.apkrevive.core.Verdict
import com.apkrevive.installer.ShizukuConnectionState
import com.apkrevive.installer.ShizukuPackageInstallerBridge
import com.apkrevive.ui.ApkReviveViewModel
import com.apkrevive.ui.ReviveJobState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class ApkReviveViewModelTest {

    private val testDispatcher = StandardTestDispatcher()

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
        ShizukuPackageInstallerBridge.uninstallExecutor = null
    }

    @After
    fun tearDown() {
        ShizukuPackageInstallerBridge.uninstallExecutor = null
        Dispatchers.resetMain()
    }

    @Test
    fun testInitialUiState() {
        val viewModel = ApkReviveViewModel()
        val state = viewModel.uiState.value

        assertFalse(state.isShizukuAvailable)
        assertFalse(state.isShizukuAuthorized)
        assertNull(state.selectedApkUri)
        assertNull(state.selectedApkName)
        assertNull(state.selectedAppLabel)
        assertEquals(0L, state.selectedApkSizeBytes)
        assertFalse(state.isAnalyzingApk)
        assertNull(state.apkMetadata)
        assertNull(state.triageResult)
        assertFalse(state.isInstalling)
        assertNull(state.installSuccess)
        assertNull(state.installedPackageName)

        // Verify initial state flows
        assertEquals(ShizukuConnectionState.ServiceStopped, viewModel.shizukuConnectionState.value)
        assertEquals(ReviveJobState.Idle, viewModel.reviveJobState.value)
    }

    @Test
    fun testSetShizukuStatusUpdatesState() {
        val viewModel = ApkReviveViewModel()
        viewModel.setShizukuStatus(available = true, authorized = true)

        val state = viewModel.uiState.value
        assertTrue(state.isShizukuAvailable)
        assertTrue(state.isShizukuAuthorized)

        val connectionState = viewModel.shizukuConnectionState.value
        assertTrue(connectionState is ShizukuConnectionState.Connected)
        val connected = connectionState as ShizukuConnectionState.Connected
        assertEquals(0, connected.uid)
        assertFalse(connected.isRootPrivilege)
    }

    @Test
    fun testSetShizukuConnectionStateSync() {
        val viewModel = ApkReviveViewModel()

        // 1. Connected
        viewModel.setShizukuConnectionState(
            ShizukuConnectionState.Connected(uid = 0, isRootPrivilege = true, binderVersion = 13)
        )
        assertTrue(viewModel.uiState.value.isShizukuAvailable)
        assertTrue(viewModel.uiState.value.isShizukuAuthorized)

        // 2. PermissionDenied
        viewModel.setShizukuConnectionState(
            ShizukuConnectionState.PermissionDenied(shouldShowRationale = true)
        )
        assertTrue(viewModel.uiState.value.isShizukuAvailable)
        assertFalse(viewModel.uiState.value.isShizukuAuthorized)

        // 3. ServiceStopped
        viewModel.setShizukuConnectionState(ShizukuConnectionState.ServiceStopped)
        assertFalse(viewModel.uiState.value.isShizukuAvailable)
        assertFalse(viewModel.uiState.value.isShizukuAuthorized)
    }

    @Test
    fun testOnPresetSelectedConfiguresTriageAndToggles() {
        val viewModel = ApkReviveViewModel()
        val sampleMeta = ApkMetadata(
            packageName = "com.legacy.arcade",
            targetSdk = 22,
            minSdk = 16,
            abis = listOf("arm64-v8a"),
            elfLoadAlign64bit = 16384L,
            sizeBytes = 8_500_000L,
            isNonResizeable = true
        )
        val deviceProfile = DeviceProfile(
            osApiLevel = 35,
            installFloor = 24,
            supportedAbis = listOf("arm64-v8a"),
            pageSizeBytes = 16384L,
            isWidescreen = true,
            isHighRefresh = true
        )

        viewModel.onPresetSelected(sampleMeta, "Arcade Classic Game", deviceProfile)

        val state = viewModel.uiState.value
        assertEquals("com.legacy.arcade.apk", state.selectedApkName)
        assertEquals("Arcade Classic Game", state.selectedAppLabel)
        assertEquals(8_500_000L, state.selectedApkSizeBytes)
        assertEquals(sampleMeta, state.apkMetadata)
        assertNotNull(state.triageResult)
        assertEquals(Verdict.YELLOW, state.triageResult?.verdict)
        assertNull(state.triageResult?.installMethod)
        assertEquals(listOf("EXPAND_ASPECT_RATIO"), state.triageResult?.requiredTransforms)

        assertTrue(state.expandAspectRatio)

        // Verify reviveJobState is ReadyForRevive
        val jobState = viewModel.reviveJobState.value
        assertTrue(jobState is ReviveJobState.ReadyForRevive)
        val ready = jobState as ReviveJobState.ReadyForRevive
        assertEquals(sampleMeta, ready.metadata)
        assertEquals(Verdict.YELLOW, ready.report.verdict)
    }

    @Test
    fun testModernizerToggles() {
        val viewModel = ApkReviveViewModel()

        assertFalse(viewModel.uiState.value.expandAspectRatio)
        viewModel.onToggleAspectRatio(true)
        assertTrue(viewModel.uiState.value.expandAspectRatio)

        assertFalse(viewModel.uiState.value.lock60Hz)
        viewModel.onToggleLock60Hz(true)
        assertTrue(viewModel.uiState.value.lock60Hz)

        assertFalse(viewModel.uiState.value.expandCutout)
        viewModel.onToggleCutout(true)
        assertTrue(viewModel.uiState.value.expandCutout)
    }

    @Test
    fun testUninstallAndRetryFailureWithoutPackage() = runTest {
        val viewModel = ApkReviveViewModel(testDispatcher)
        // No APK selected -> uninstallAndRetry should transition to InstallFailed
        viewModel.uninstallAndRetry(null)
        testScheduler.advanceUntilIdle()

        val jobState = viewModel.reviveJobState.value
        assertTrue(jobState is ReviveJobState.InstallFailed)
        val failed = jobState as ReviveJobState.InstallFailed
        assertEquals(-1, failed.errorCode)
        assertTrue(failed.humanExplanation.contains("No package"))
    }

    @Test
    fun testUninstallAndRetryHookExecution() = runTest {
        val viewModel = ApkReviveViewModel(testDispatcher)
        val sampleMeta = ApkMetadata(
            packageName = "com.conflicting.pkg",
            targetSdk = 22,
            sizeBytes = 1_000_000L
        )
        viewModel.onPresetSelected(sampleMeta, "Conflicting App")

        var uninstalledPkg: String? = null
        ShizukuPackageInstallerBridge.uninstallExecutor = { pkg ->
            uninstalledPkg = pkg
            Result.failure(Exception("Package manager uninstallation rejected"))
        }

        viewModel.uninstallAndRetry(null)
        testScheduler.advanceUntilIdle()

        assertEquals("com.conflicting.pkg", uninstalledPkg)
        val jobState = viewModel.reviveJobState.value
        assertTrue(jobState is ReviveJobState.InstallFailed)
        val failed = jobState as ReviveJobState.InstallFailed
        assertEquals(-7, failed.errorCode)
        assertTrue(failed.humanExplanation.contains("Failed to uninstall conflicting package"))
        assertTrue(failed.remediation.contains("manually"))
    }
}