package com.apkrevive.ui

import android.content.Context
import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.apkrevive.core.ApkInspector
import com.apkrevive.core.ApkMetadata
import com.apkrevive.core.DeviceProfile
import com.apkrevive.core.TriageEvaluator
import com.apkrevive.core.TriageResult
import com.apkrevive.installer.InstallResultReceiver
import com.apkrevive.installer.ShizukuPackageInstallerBridge
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

data class ApkReviveUiState(
    val isShizukuAvailable: Boolean = false,
    val isShizukuAuthorized: Boolean = false,
    val selectedApkUri: Uri? = null,
    val selectedApkName: String? = null,
    val selectedAppLabel: String? = null,
    val selectedApkSizeBytes: Long = 0L,
    val isAnalyzingApk: Boolean = false,
    val apkMetadata: ApkMetadata? = null,
    val triageResult: TriageResult? = null,
    val expandAspectRatio: Boolean = false,
    val lock60Hz: Boolean = false,
    val expandCutout: Boolean = false,
    val isInstalling: Boolean = false,
    val installStatusMessage: String? = null,
    val installSuccess: Boolean? = null,
    val installedPackageName: String? = null
)

class ApkReviveViewModel : ViewModel() {

    private val _uiState = MutableStateFlow(ApkReviveUiState())
    val uiState: StateFlow<ApkReviveUiState> = _uiState.asStateFlow()

    init {
        viewModelScope.launch {
            InstallResultReceiver.events.collect { event ->
                _uiState.update { current ->
                    current.copy(
                        isInstalling = false,
                        installSuccess = event.isSuccess,
                        installStatusMessage = event.message,
                        installedPackageName = if (event.isSuccess) current.apkMetadata?.packageName else current.installedPackageName
                    )
                }
            }
        }
    }

    fun setShizukuStatus(available: Boolean, authorized: Boolean) {
        _uiState.update {
            it.copy(
                isShizukuAvailable = available,
                isShizukuAuthorized = authorized
            )
        }
    }

    fun onFileSelected(context: Context, uri: Uri) {
        _uiState.update {
            it.copy(
                selectedApkUri = uri,
                isAnalyzingApk = true,
                installStatusMessage = null,
                installSuccess = null
            )
        }

        viewModelScope.launch(Dispatchers.IO) {
            val (name, size) = queryFileInfo(context, uri)
            val deviceProfile = getHostDeviceProfile(context)
            val inspectionResult = ApkInspector.inspectApk(context, uri, size)

            inspectionResult.fold(
                onSuccess = { inspection ->
                    val meta = inspection.metadata
                    val triage = TriageEvaluator.evaluateTriage(meta, deviceProfile)

                    _uiState.update {
                        it.copy(
                            selectedApkName = name,
                            selectedApkSizeBytes = size,
                            selectedAppLabel = inspection.appLabel,
                            apkMetadata = meta,
                            triageResult = triage,
                            isAnalyzingApk = false,
                            expandAspectRatio = "EXPAND_ASPECT_RATIO" in triage.requiredTransforms || meta.isNonResizeable,
                            lock60Hz = "LOCK_60HZ_DISPLAY_MODE" in triage.requiredTransforms || meta.hasFixedPhysics,
                            expandCutout = "EXPAND_ASPECT_RATIO" in triage.requiredTransforms
                        )
                    }
                },
                onFailure = { error ->
                    _uiState.update {
                        it.copy(
                            selectedApkName = name,
                            selectedApkSizeBytes = size,
                            selectedAppLabel = null,
                            apkMetadata = null,
                            triageResult = null,
                            isAnalyzingApk = false,
                            installStatusMessage = "Failed to inspect APK: ${error.message ?: "Invalid or corrupted file"}"
                        )
                    }
                }
            )
        }
    }

    fun onPresetSelected(
        sampleMeta: ApkMetadata,
        sampleLabel: String,
        deviceProfile: DeviceProfile = getHostDeviceProfile()
    ) {
        val triage = TriageEvaluator.evaluateTriage(sampleMeta, deviceProfile)
        _uiState.update {
            it.copy(
                selectedApkUri = null,
                selectedApkName = "${sampleMeta.packageName}.apk",
                selectedAppLabel = sampleLabel,
                selectedApkSizeBytes = sampleMeta.sizeBytes,
                apkMetadata = sampleMeta,
                triageResult = triage,
                isAnalyzingApk = false,
                expandAspectRatio = "EXPAND_ASPECT_RATIO" in triage.requiredTransforms || sampleMeta.isNonResizeable,
                lock60Hz = "LOCK_60HZ_DISPLAY_MODE" in triage.requiredTransforms || sampleMeta.hasFixedPhysics,
                expandCutout = "EXPAND_ASPECT_RATIO" in triage.requiredTransforms,
                installStatusMessage = null,
                installSuccess = null
            )
        }
    }

    fun onToggleAspectRatio(enabled: Boolean) {
        _uiState.update { it.copy(expandAspectRatio = enabled) }
    }

    fun onToggleLock60Hz(enabled: Boolean) {
        _uiState.update { it.copy(lock60Hz = enabled) }
    }

    fun onToggleCutout(enabled: Boolean) {
        _uiState.update { it.copy(expandCutout = enabled) }
    }

    fun installApk(context: Context) {
        val currentState = _uiState.value
        val uri = currentState.selectedApkUri
        if (uri == null) {
            _uiState.update { it.copy(installStatusMessage = "Please select a downloaded app file to install.") }
            return
        }

        _uiState.update {
            it.copy(
                isInstalling = true,
                installStatusMessage = "Preparing to install...",
                installSuccess = null
            )
        }

        viewModelScope.launch(Dispatchers.IO) {
            try {
                val stream = context.contentResolver.openInputStream(uri)
                if (stream == null) {
                    _uiState.update {
                        it.copy(
                            isInstalling = false,
                            installStatusMessage = "Could not open file. Please select it again.",
                            installSuccess = false
                        )
                    }
                    return@launch
                }

                val deviceProfile = getHostDeviceProfile(context)
                val bypass = currentState.triageResult?.installMethod == "BYPASS_LOW_TARGET_SDK_BLOCK" ||
                        (currentState.apkMetadata?.targetSdk ?: 35) < deviceProfile.installFloor

                _uiState.update {
                    it.copy(installStatusMessage = "Installing app. This may take a moment...")
                }

                val result = ShizukuPackageInstallerBridge.installApk(
                    context = context,
                    apkStream = stream,
                    apkSize = currentState.selectedApkSizeBytes,
                    bypassLowTargetSdk = bypass
                )

                result.fold(
                    onSuccess = {
                        _uiState.update {
                            it.copy(
                                isInstalling = false,
                                installSuccess = true,
                                installStatusMessage = "Installation succeeded!",
                                installedPackageName = currentState.apkMetadata?.packageName
                            )
                        }
                    },
                    onFailure = { error ->
                        _uiState.update {
                            it.copy(
                                isInstalling = false,
                                installSuccess = false,
                                installStatusMessage = "Installation failed: ${error.message ?: "Unknown error"}"
                            )
                        }
                    }
                )
            } catch (t: Throwable) {
                _uiState.update {
                    it.copy(
                        isInstalling = false,
                        installSuccess = false,
                        installStatusMessage = "Something went wrong: ${t.message ?: "Please try again."}"
                    )
                }
            }
        }
    }
}
