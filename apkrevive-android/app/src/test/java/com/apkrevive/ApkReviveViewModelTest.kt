package com.apkrevive

import com.apkrevive.core.ApkMetadata
import com.apkrevive.core.DeviceProfile
import com.apkrevive.core.Verdict
import com.apkrevive.ui.ApkReviveViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
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
    }

    @After
    fun tearDown() {
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
    }

    @Test
    fun testSetShizukuStatusUpdatesState() {
        val viewModel = ApkReviveViewModel()
        viewModel.setShizukuStatus(available = true, authorized = true)

        val state = viewModel.uiState.value
        assertTrue(state.isShizukuAvailable)
        assertTrue(state.isShizukuAuthorized)
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

        // isNonResizeable should automatically set expandAspectRatio = true
        assertTrue(state.expandAspectRatio)
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
}
