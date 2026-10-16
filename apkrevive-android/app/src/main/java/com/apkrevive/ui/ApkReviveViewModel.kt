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
import com.apkrevive.installer.ShizukuConnectionState
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

class ApkReviveViewModel(
    private val ioDispatcher: kotlinx.coroutines.CoroutineDispatcher = Dispatchers.IO
) : ViewModel() {

    private val _uiState = MutableStateFlow(ApkReviveUiState())
    val uiState: StateFlow<ApkReviveUiState> = _uiState.asStateFlow()

    private val _shizukuConnectionState = MutableStateFlow<ShizukuConnectionState>(ShizukuConnectionState.ServiceStopped)
    val shizukuConnectionState: StateFlow<ShizukuConnectionState> = _shizukuConnectionState.asStateFlow()

    private val _reviveJobState = MutableStateFlow<ReviveJobState>(ReviveJobState.Idle)
    val reviveJobState: StateFlow<ReviveJobState> = _reviveJobState.asStateFlow()

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

                if (event.isSuccess) {
                    _reviveJobState.value = ReviveJobState.InstallSuccess(
                        _uiState.value.apkMetadata?.packageName ?: ""
                    )
                } else {
                    val explanation = ShizukuPackageInstallerBridge.parseInstallError(event.errorCode, event.message)
                    _reviveJobState.value = ReviveJobState.InstallFailed(
                        errorCode = explanation.errorCode,
                        humanExplanation = explanation.humanExplanation,
                        remediation = explanation.remediation
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
        _shizukuConnectionState.value = when {
            authorized -> ShizukuConnectionState.Connected(uid = 0, isRootPrivilege = false, binderVersion = 13)
            available -> ShizukuConnectionState.PermissionDenied(shouldShowRationale = false)
            else -> ShizukuConnectionState.ServiceStopped
        }
    }

    fun setShizukuConnectionState(state: ShizukuConnectionState) {
        _shizukuConnectionState.value = state
        val available = state !is ShizukuConnectionState.NotInstalled && state !is ShizukuConnectionState.ServiceStopped
        val authorized = state is ShizukuConnectionState.Connected
        _uiState.update {
            it.copy(
                isShizukuAvailable = available,
                isShizukuAuthorized = authorized
            )
        }
    }

    fun refreshShizukuConnection(context: Context? = null) {
        val state = ShizukuPackageInstallerBridge.checkConnectionState(context)
        setShizukuConnectionState(state)
    }

    fun onFileSelected(context: Context, uri: Uri) {
        _reviveJobState.value = ReviveJobState.Inspecting
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

                    _reviveJobState.value = ReviveJobState.ReadyForRevive(triage, meta)
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
                    val msg = "Failed to inspect APK: ${error.message ?: "Invalid or corrupted file"}"
                    _reviveJobState.value = ReviveJobState.InstallFailed(
                        errorCode = -1,
                        humanExplanation = msg,
                        remediation = "Verify the APK file is not damaged and retry."
                    )
                    _uiState.update {
                        it.copy(
                            selectedApkName = name,
                            selectedApkSizeBytes = size,
                            selectedAppLabel = null,
                            apkMetadata = null,
                            triageResult = null,
                            isAnalyzingApk = false,
                            installStatusMessage = msg
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
        _reviveJobState.value = ReviveJobState.ReadyForRevive(triage, sampleMeta)
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
            val msg = "Please select a downloaded app file to install."
            _uiState.update { it.copy(installStatusMessage = msg) }
            _reviveJobState.value = ReviveJobState.InstallFailed(-1, msg, "Choose an APK file from device storage.")
            return
        }

        _uiState.update {
            it.copy(
                isInstalling = true,
                installStatusMessage = "Preparing to install...",
                installSuccess = null
            )
        }
        _reviveJobState.value = ReviveJobState.ExecutingPipeline(
            step = "Opening Stream",
            stepIndex = 0,
            totalSteps = 4,
            progressFraction = 0.1f
        )

        viewModelScope.launch(Dispatchers.IO) {
            try {
                val stream = context.contentResolver.openInputStream(uri)
                if (stream == null) {
                    val msg = "Could not open file. Please select it again."
                    _uiState.update {
                        it.copy(
                            isInstalling = false,
                            installStatusMessage = msg,
                            installSuccess = false
                        )
                    }
                    _reviveJobState.value = ReviveJobState.InstallFailed(-1, msg, "Re-select the file using the picker.")
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
                    bypassLowTargetSdk = bypass,
                    onProgress = { step, index, total, fraction ->
                        _reviveJobState.value = ReviveJobState.ExecutingPipeline(
                            step = step,
                            stepIndex = index,
                            totalSteps = total,
                            progressFraction = fraction
                        )
                    }
                )

                result.fold(
                    onSuccess = {
                        val pkg = currentState.apkMetadata?.packageName ?: ""
                        _reviveJobState.value = ReviveJobState.InstallSuccess(pkg)
                        _uiState.update {
                            it.copy(
                                isInstalling = false,
                                installSuccess = true,
                                installStatusMessage = "Installation succeeded!",
                                installedPackageName = pkg
                            )
                        }
                    },
                    onFailure = { error ->
                        val errCode = if (error is ShizukuPackageInstallerBridge.SessionInstallException) {
                            error.errorCode
                        } else if (error.message?.contains("INSTALL_FAILED_UPDATE_INCOMPATIBLE") == true) {
                            ShizukuPackageInstallerBridge.INSTALL_FAILED_UPDATE_INCOMPATIBLE
                        } else {
                            -1
                        }
                        val explanation = ShizukuPackageInstallerBridge.parseInstallError(errCode, error.message)
                        _reviveJobState.value = ReviveJobState.InstallFailed(
                            errorCode = explanation.errorCode,
                            humanExplanation = explanation.humanExplanation,
                            remediation = explanation.remediation
                        )
                        _uiState.update {
                            it.copy(
                                isInstalling = false,
                                installSuccess = false,
                                installStatusMessage = "Installation failed: ${explanation.humanExplanation}"
                            )
                        }
                    }
                )
            } catch (t: Throwable) {
                val explanation = ShizukuPackageInstallerBridge.parseInstallError(-1, t.message)
                _reviveJobState.value = ReviveJobState.InstallFailed(
                    errorCode = explanation.errorCode,
                    humanExplanation = explanation.humanExplanation,
                    remediation = explanation.remediation
                )
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

    fun uninstallAndRetry(context: Context? = null) {
        val pkgName = _uiState.value.apkMetadata?.packageName
        if (pkgName.isNullOrBlank()) {
            val msg = "No package specified to uninstall."
            _uiState.update { it.copy(installStatusMessage = msg) }
            _reviveJobState.value = ReviveJobState.InstallFailed(-1, msg, "Select an APK first.")
            return
        }

        _uiState.update {
            it.copy(
                isInstalling = true,
                installStatusMessage = "Uninstalling conflicting app...",
                installSuccess = null
            )
        }
        _reviveJobState.value = ReviveJobState.ExecutingPipeline(
            step = "Uninstalling Conflicting Version",
            stepIndex = 0,
            totalSteps = 5,
            progressFraction = 0.05f
        )

        viewModelScope.launch(ioDispatcher) {
            val uninstallResult = ShizukuPackageInstallerBridge.uninstallPackage(context, pkgName)
            uninstallResult.fold(
                onSuccess = {
                    if (context != null) {
                        installApk(context)
                    }
                },
                onFailure = { error ->
                    val explanation = ShizukuPackageInstallerBridge.parseInstallError(
                        ShizukuPackageInstallerBridge.INSTALL_FAILED_UPDATE_INCOMPATIBLE,
                        "Failed to uninstall conflicting package: ${error.message}"
                    )
                    _reviveJobState.value = ReviveJobState.InstallFailed(
                        errorCode = explanation.errorCode,
                        humanExplanation = "Failed to uninstall conflicting package $pkgName: ${error.message ?: "Unknown error"}",
                        remediation = "Uninstall the existing version manually from Settings, then retry."
                    )
                    _uiState.update {
                        it.copy(
                            isInstalling = false,
                            installSuccess = false,
                            installStatusMessage = "Failed to uninstall existing app."
                        )
                    }
                }
            )
        }
    }
}