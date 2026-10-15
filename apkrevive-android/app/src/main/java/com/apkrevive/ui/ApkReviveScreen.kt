package com.apkrevive.ui

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.OpenableColumns
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.HelpOutline
import androidx.compose.material.icons.filled.Cancel
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.SystemUpdate
import androidx.compose.material.icons.filled.Tune
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SuggestionChip
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.apkrevive.R
import com.apkrevive.core.ApkInspectionResult
import com.apkrevive.core.ApkInspector
import com.apkrevive.core.ApkMetadata
import com.apkrevive.core.DeviceProfile
import com.apkrevive.core.TriageEvaluator
import com.apkrevive.core.TriageResult
import com.apkrevive.core.TriageSignal
import com.apkrevive.core.Verdict
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ApkReviveScreen(
    viewModel: ApkReviveViewModel = androidx.lifecycle.viewmodel.compose.viewModel(),
    onRequestShizukuPermission: () -> Unit,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val scrollState = rememberScrollState()
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()

    // Host device profile
    val deviceProfile = remember { getHostDeviceProfile(context) }

    // SAF Document Picker
    val safLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        if (uri != null) {
            viewModel.onFileSelected(context, uri)
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text(
                            text = stringResource(R.string.app_title),
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = stringResource(R.string.app_subtitle),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surfaceContainer
                )
            )
        },
        modifier = modifier
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .verticalScroll(scrollState)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // 0. Onboarding Stepper (M3 Indicator Card)
            OnboardingStepperCard(
                isShizukuAuthorized = uiState.isShizukuAuthorized,
                hasSelectedApk = uiState.apkMetadata != null,
                isInstalled = uiState.installSuccess == true
            )

            // Post-Install Success Card (Shown when installSuccess == true and installedPackageName != null)
            if (uiState.installSuccess == true && uiState.installedPackageName != null) {
                PostInstallCard(
                    packageName = uiState.installedPackageName!!,
                    appLabel = uiState.selectedAppLabel
                )
            }

            // 1. Shizuku Service Card
            ShizukuStatusCard(
                isAvailable = uiState.isShizukuAvailable,
                isAuthorized = uiState.isShizukuAuthorized,
                onRequestPermission = onRequestShizukuPermission
            )

            // 2. App Selector Card (Picker & Presets)
            FilePickerCard(
                selectedFileName = uiState.selectedApkName,
                selectedAppLabel = uiState.selectedAppLabel,
                selectedSizeBytes = uiState.selectedApkSizeBytes,
                isAnalyzing = uiState.isAnalyzingApk,
                onPickFile = {
                    safLauncher.launch(arrayOf("application/vnd.android.package-archive", "*/*"))
                },
                onLoadSampleVector = { sampleMeta, sampleLabel ->
                    viewModel.onPresetSelected(sampleMeta, sampleLabel, deviceProfile)
                }
            )

            // 3. Compatibility Summary (Triage Card)
            if (uiState.triageResult != null && uiState.apkMetadata != null) {
                TriageResultCard(
                    apkMeta = uiState.apkMetadata!!,
                    deviceProfile = deviceProfile,
                    triage = uiState.triageResult!!
                )
            }

            // 4. Modernization Feature Toggles Card (hidden until app analyzed)
            if (uiState.triageResult != null && uiState.apkMetadata != null) {
                ModernizerTogglesCard(
                    expandAspectRatio = uiState.expandAspectRatio,
                    onExpandAspectRatioChange = { viewModel.onToggleAspectRatio(it) },
                    lock60Hz = uiState.lock60Hz,
                    onLock60HzChange = { viewModel.onToggleLock60Hz(it) },
                    expandCutout = uiState.expandCutout,
                    onExpandCutoutChange = { viewModel.onToggleCutout(it) }
                )
            }

            // 5. Primary Action Button Card
            InstallActionCard(
                canInstall = uiState.isShizukuAuthorized && uiState.selectedApkUri != null && uiState.triageResult?.verdict != Verdict.RED,
                isInstalling = uiState.isInstalling,
                isShizukuAuthorized = uiState.isShizukuAuthorized,
                isShizukuAvailable = uiState.isShizukuAvailable,
                triageResult = uiState.triageResult,
                installStatusMessage = uiState.installStatusMessage,
                installSuccess = uiState.installSuccess,
                onInstallClick = {
                    viewModel.installApk(context)
                },
                onRequestPermission = onRequestShizukuPermission
            )

            Spacer(modifier = Modifier.height(24.dp))
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ApkReviveScreen(
    isShizukuAvailable: Boolean,
    isShizukuAuthorized: Boolean,
    onRequestShizukuPermission: () -> Unit,
    modifier: Modifier = Modifier
) {
    val viewModel: ApkReviveViewModel = androidx.lifecycle.viewmodel.compose.viewModel()
    LaunchedEffect(isShizukuAvailable, isShizukuAuthorized) {
        viewModel.setShizukuStatus(isShizukuAvailable, isShizukuAuthorized)
    }
    ApkReviveScreen(
        viewModel = viewModel,
        onRequestShizukuPermission = onRequestShizukuPermission,
        modifier = modifier
    )
}

// ---------------------------------------------------------------------------
// 0. Onboarding Stepper (3-step visual progress)
// ---------------------------------------------------------------------------
@Composable
fun OnboardingStepperCard(
    isShizukuAuthorized: Boolean,
    hasSelectedApk: Boolean,
    isInstalled: Boolean,
    modifier: Modifier = Modifier
) {
    ElevatedCard(
        modifier = modifier.fillMaxWidth(),
        colors = CardDefaults.elevatedCardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainer
        )
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Text(
                text = stringResource(R.string.stepper_title),
                style = MaterialTheme.typography.labelLarge,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.primary,
                modifier = Modifier.semantics { heading() }
            )

            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                StepItem(
                    stepNumber = 1,
                    title = stringResource(R.string.step_shizuku),
                    isDone = isShizukuAuthorized,
                    isActive = !isShizukuAuthorized,
                    modifier = Modifier.weight(1f)
                )

                HorizontalDivider(
                    modifier = Modifier
                        .width(20.dp)
                        .padding(horizontal = 2.dp),
                    color = if (isShizukuAuthorized) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outlineVariant
                )

                StepItem(
                    stepNumber = 2,
                    title = stringResource(R.string.step_select_apk),
                    isDone = hasSelectedApk,
                    isActive = isShizukuAuthorized && !hasSelectedApk,
                    modifier = Modifier.weight(1f)
                )

                HorizontalDivider(
                    modifier = Modifier
                        .width(20.dp)
                        .padding(horizontal = 2.dp),
                    color = if (hasSelectedApk) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outlineVariant
                )

                StepItem(
                    stepNumber = 3,
                    title = stringResource(R.string.step_install),
                    isDone = isInstalled,
                    isActive = hasSelectedApk && !isInstalled,
                    modifier = Modifier.weight(1f)
                )
            }
        }
    }
}

@Composable
private fun StepItem(
    stepNumber: Int,
    title: String,
    isDone: Boolean,
    isActive: Boolean,
    modifier: Modifier = Modifier
) {
    Column(
        modifier = modifier,
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(6.dp)
    ) {
        Surface(
            shape = CircleShape,
            color = when {
                isDone -> MaterialTheme.colorScheme.primary
                isActive -> MaterialTheme.colorScheme.primaryContainer
                else -> MaterialTheme.colorScheme.surfaceContainerHighest
            },
            contentColor = when {
                isDone -> MaterialTheme.colorScheme.onPrimary
                isActive -> MaterialTheme.colorScheme.onPrimaryContainer
                else -> MaterialTheme.colorScheme.onSurfaceVariant
            },
            modifier = Modifier.size(28.dp)
        ) {
            Box(
                contentAlignment = Alignment.Center,
                modifier = Modifier.fillMaxSize()
            ) {
                if (isDone) {
                    Icon(
                        imageVector = Icons.Default.Check,
                        contentDescription = stringResource(R.string.step_completed),
                        modifier = Modifier.size(16.dp)
                    )
                } else {
                    Text(
                        text = stepNumber.toString(),
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = if (isActive) FontWeight.Bold else FontWeight.Normal
                    )
                }
            }
        }

        Text(
            text = title,
            style = MaterialTheme.typography.labelSmall,
            fontWeight = if (isActive || isDone) FontWeight.SemiBold else FontWeight.Normal,
            color = if (isActive || isDone) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
            maxLines = 2,
            lineHeight = 14.sp
        )
    }
}

// ---------------------------------------------------------------------------
// Post-Install Success Card
// ---------------------------------------------------------------------------
@Composable
fun PostInstallCard(
    packageName: String,
    appLabel: String?,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val displayName = appLabel ?: packageName

    ElevatedCard(
        modifier = modifier.fillMaxWidth(),
        colors = CardDefaults.elevatedCardColors(
            containerColor = MaterialTheme.colorScheme.primaryContainer
        )
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Icon(
                    imageVector = Icons.Default.CheckCircle,
                    contentDescription = stringResource(R.string.post_install_icon_desc),
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(28.dp)
                )
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = stringResource(R.string.post_install_title),
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.onPrimaryContainer,
                        modifier = Modifier.semantics { heading() }
                    )
                    Text(
                        text = stringResource(R.string.post_install_subtitle, displayName),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.85f)
                    )
                }
            }

            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                // Large "Launch App" button (min height 56dp)
                Button(
                    onClick = {
                        val launchIntent = context.packageManager.getLaunchIntentForPackage(packageName)
                        if (launchIntent != null) {
                            context.startActivity(launchIntent)
                        }
                    },
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 56.dp),
                    shape = RoundedCornerShape(12.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.primary,
                        contentColor = MaterialTheme.colorScheme.onPrimary
                    )
                ) {
                    Icon(
                        imageVector = Icons.Default.PlayArrow,
                        contentDescription = null,
                        modifier = Modifier.size(22.dp)
                    )
                    Spacer(modifier = Modifier.width(10.dp))
                    Text(
                        text = stringResource(R.string.btn_launch_app),
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold
                    )
                }

                // "App Settings" button (min height 48dp)
                OutlinedButton(
                    onClick = {
                        val intent = Intent(
                            Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                            Uri.parse("package:$packageName")
                        )
                        context.startActivity(intent)
                    },
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 48.dp),
                    shape = RoundedCornerShape(12.dp)
                ) {
                    Icon(
                        imageVector = Icons.Default.Settings,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = stringResource(R.string.btn_app_settings),
                        style = MaterialTheme.typography.labelLarge,
                        fontWeight = FontWeight.SemiBold
                    )
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 1. Shizuku Status Card
// ---------------------------------------------------------------------------
@Composable
fun ShizukuStatusCard(
    isAvailable: Boolean,
    isAuthorized: Boolean,
    onRequestPermission: () -> Unit
) {
    val context = LocalContext.current
    var isSetupExpanded by remember { mutableStateOf(false) }

    if (isAuthorized) {
        Surface(
            shape = RoundedCornerShape(12.dp),
            color = MaterialTheme.colorScheme.primaryContainer,
            modifier = Modifier.fillMaxWidth()
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Icon(
                        imageVector = Icons.Default.CheckCircle,
                        contentDescription = stringResource(R.string.shizuku_ready_title),
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(24.dp)
                    )
                    Column {
                        Text(
                            text = stringResource(R.string.shizuku_ready_title),
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.onPrimaryContainer,
                            modifier = Modifier.semantics { heading() }
                        )
                        Text(
                            text = stringResource(R.string.shizuku_ready_subtitle),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.8f)
                        )
                    }
                }
                Surface(
                    shape = RoundedCornerShape(8.dp),
                    color = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.padding(2.dp)
                ) {
                    Text(
                        text = stringResource(R.string.shizuku_status_authorized),
                        color = MaterialTheme.colorScheme.onPrimary,
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                    )
                }
            }
        }
    } else {
        ElevatedCard(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.elevatedCardColors(
                containerColor = MaterialTheme.colorScheme.surfaceContainer
            )
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Icon(
                        imageVector = Icons.Default.Security,
                        contentDescription = null,
                        tint = if (isAvailable) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
                        modifier = Modifier.size(28.dp)
                    )
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = stringResource(R.string.shizuku_req_title),
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.onSurface,
                            modifier = Modifier.semantics { heading() }
                        )
                        Text(
                            text = if (isAvailable) {
                                stringResource(R.string.shizuku_req_subtitle_permission)
                            } else {
                                stringResource(R.string.shizuku_req_subtitle_stopped)
                            },
                            style = MaterialTheme.typography.bodySmall,
                            color = if (isAvailable) MaterialTheme.colorScheme.onSurfaceVariant else MaterialTheme.colorScheme.error
                        )
                    }
                }

                Text(
                    text = stringResource(R.string.shizuku_description),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    if (isAvailable) {
                        Button(
                            onClick = onRequestPermission,
                            modifier = Modifier
                                .fillMaxWidth()
                                .heightIn(min = 48.dp),
                            shape = RoundedCornerShape(10.dp),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = MaterialTheme.colorScheme.primary
                            )
                        ) {
                            Icon(
                                imageVector = Icons.Default.Security,
                                contentDescription = null,
                                modifier = Modifier.size(18.dp)
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                text = stringResource(R.string.btn_request_permission),
                                style = MaterialTheme.typography.labelLarge,
                                fontWeight = FontWeight.SemiBold
                            )
                        }
                    } else {
                        Button(
                            onClick = {
                                val launchIntent = context.packageManager.getLaunchIntentForPackage("moe.shizuku.privileged.api")
                                if (launchIntent != null) {
                                    context.startActivity(launchIntent)
                                } else {
                                    val webIntent = Intent(Intent.ACTION_VIEW, Uri.parse("https://shizuku.rikka.app"))
                                    context.startActivity(webIntent)
                                }
                            },
                            modifier = Modifier
                                .weight(1f)
                                .heightIn(min = 48.dp),
                            shape = RoundedCornerShape(10.dp),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = MaterialTheme.colorScheme.primary
                            )
                        ) {
                            Text(
                                text = stringResource(R.string.btn_open_shizuku),
                                style = MaterialTheme.typography.labelLarge,
                                fontWeight = FontWeight.SemiBold
                            )
                        }

                        OutlinedButton(
                            onClick = onRequestPermission,
                            modifier = Modifier.heightIn(min = 48.dp),
                            shape = RoundedCornerShape(10.dp)
                        ) {
                            Icon(
                                imageVector = Icons.Default.Refresh,
                                contentDescription = null,
                                modifier = Modifier.size(18.dp)
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(stringResource(R.string.btn_retry))
                        }
                    }
                }

                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)

                // Expandable setup tip card
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 48.dp)
                        .clip(RoundedCornerShape(8.dp))
                        .clickable { isSetupExpanded = !isSetupExpanded }
                        .padding(vertical = 4.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.HelpOutline,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(18.dp)
                        )
                        Text(
                            text = stringResource(R.string.shizuku_guide_title),
                            style = MaterialTheme.typography.labelLarge,
                            fontWeight = FontWeight.SemiBold,
                            color = MaterialTheme.colorScheme.primary
                        )
                    }
                    IconButton(
                        onClick = { isSetupExpanded = !isSetupExpanded },
                        modifier = Modifier.size(48.dp)
                    ) {
                        Icon(
                            imageVector = if (isSetupExpanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                            contentDescription = if (isSetupExpanded) stringResource(R.string.collapse_setup_tips) else stringResource(R.string.expand_setup_tips),
                            tint = MaterialTheme.colorScheme.primary
                        )
                    }
                }

                AnimatedVisibility(visible = isSetupExpanded) {
                    Surface(
                        shape = RoundedCornerShape(10.dp),
                        color = MaterialTheme.colorScheme.surfaceContainerHighest,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(
                            modifier = Modifier.padding(12.dp),
                            verticalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Text(
                                text = stringResource(R.string.shizuku_guide_steps_header),
                                style = MaterialTheme.typography.labelMedium,
                                fontWeight = FontWeight.Bold,
                                color = MaterialTheme.colorScheme.onSurface
                            )
                            Text(
                                text = stringResource(R.string.shizuku_guide_steps),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                lineHeight = 18.sp
                            )
                        }
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 2. SAF File Picker Card + Presets
// ---------------------------------------------------------------------------
@Composable
fun FilePickerCard(
    selectedFileName: String?,
    selectedAppLabel: String?,
    selectedSizeBytes: Long,
    isAnalyzing: Boolean,
    onPickFile: () -> Unit,
    onLoadSampleVector: (ApkMetadata, String) -> Unit
) {
    ElevatedCard(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.elevatedCardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainer
        )
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            Text(
                text = stringResource(R.string.picker_title),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onSurface,
                modifier = Modifier.semantics { heading() }
            )

            if (selectedFileName == null) {
                Button(
                    onClick = onPickFile,
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 48.dp),
                    shape = RoundedCornerShape(12.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.primary
                    )
                ) {
                    Icon(
                        imageVector = Icons.Default.FolderOpen,
                        contentDescription = null,
                        modifier = Modifier.size(20.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = stringResource(R.string.btn_choose_apk),
                        style = MaterialTheme.typography.labelLarge,
                        fontWeight = FontWeight.SemiBold
                    )
                }
            } else {
                Surface(
                    shape = RoundedCornerShape(12.dp),
                    color = MaterialTheme.colorScheme.surfaceContainerHighest,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(14.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            if (!selectedAppLabel.isNullOrBlank()) {
                                Text(
                                    text = selectedAppLabel,
                                    style = MaterialTheme.typography.titleSmall,
                                    fontWeight = FontWeight.Bold,
                                    color = MaterialTheme.colorScheme.onSurface
                                )
                            }
                            Text(
                                text = selectedFileName,
                                style = MaterialTheme.typography.bodyMedium,
                                fontWeight = if (selectedAppLabel.isNullOrBlank()) FontWeight.SemiBold else FontWeight.Normal,
                                color = if (selectedAppLabel.isNullOrBlank()) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            Spacer(modifier = Modifier.height(2.dp))
                            Text(
                                text = stringResource(R.string.label_file_size, formatBytes(selectedSizeBytes)),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }

                        if (isAnalyzing) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(24.dp),
                                strokeWidth = 2.5.dp,
                                color = MaterialTheme.colorScheme.primary
                            )
                        } else {
                            OutlinedButton(
                                onClick = onPickFile,
                                modifier = Modifier.heightIn(min = 48.dp),
                                shape = RoundedCornerShape(8.dp)
                            ) {
                                Icon(
                                    imageVector = Icons.Default.FolderOpen,
                                    contentDescription = null,
                                    modifier = Modifier.size(16.dp)
                                )
                                Spacer(modifier = Modifier.width(6.dp))
                                Text(
                                    text = stringResource(R.string.btn_choose_another),
                                    style = MaterialTheme.typography.labelMedium
                                )
                            }
                        }
                    }
                }
            }

            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)

            Text(
                text = stringResource(R.string.sample_apps_label),
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.Medium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                SuggestionChip(
                    onClick = {
                        onLoadSampleVector(
                            ApkMetadata(
                                packageName = "com.legacy.arcade",
                                targetSdk = 22,
                                minSdk = 16,
                                abis = listOf("arm64-v8a"),
                                elfLoadAlign64bit = 16384L,
                                sizeBytes = 8_500_000L
                            ),
                            "Arcade Classic Game"
                        )
                    },
                    modifier = Modifier.heightIn(min = 48.dp),
                    label = { Text(stringResource(R.string.sample_arcade_chip), style = MaterialTheme.typography.labelSmall) }
                )
                SuggestionChip(
                    onClick = {
                        onLoadSampleVector(
                            ApkMetadata(
                                packageName = "com.legacy.httpgame",
                                targetSdk = 28,
                                minSdk = 21,
                                usesApacheHttp = true,
                                sizeBytes = 12_000_000L
                            ),
                            "Legacy HTTP Game"
                        )
                    },
                    modifier = Modifier.heightIn(min = 48.dp),
                    label = { Text(stringResource(R.string.sample_http_chip), style = MaterialTheme.typography.labelSmall) }
                )
                SuggestionChip(
                    onClick = {
                        onLoadSampleVector(
                            ApkMetadata(
                                packageName = "com.blocked.arm32",
                                targetSdk = 22,
                                minSdk = 16,
                                abis = listOf("armeabi-v7a"),
                                sizeBytes = 15_000_000L
                            ),
                            "32-bit Native Game"
                        )
                    },
                    modifier = Modifier.heightIn(min = 48.dp),
                    label = { Text(stringResource(R.string.sample_arm32_chip), style = MaterialTheme.typography.labelSmall) }
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 3. Triage Result Card
// ---------------------------------------------------------------------------
private data class TriagePresentation(
    val title: String,
    val subtitle: String,
    val containerColor: Color,
    val contentColor: Color,
    val icon: ImageVector
)

@Composable
fun TriageResultCard(
    apkMeta: ApkMetadata,
    deviceProfile: DeviceProfile,
    triage: TriageResult
) {
    var isDiagnosticsExpanded by remember { mutableStateOf(false) }

    val presentation = when (triage.verdict) {
        Verdict.GREEN -> TriagePresentation(
            title = stringResource(R.string.triage_green_title),
            subtitle = if (triage.installMethod == "BYPASS_LOW_TARGET_SDK_BLOCK") {
                stringResource(R.string.triage_green_bypass_desc)
            } else {
                stringResource(R.string.triage_green_direct_desc)
            },
            containerColor = MaterialTheme.colorScheme.primaryContainer,
            contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
            icon = Icons.Default.CheckCircle
        )
        Verdict.YELLOW -> TriagePresentation(
            title = stringResource(R.string.triage_yellow_title),
            subtitle = stringResource(R.string.triage_yellow_desc),
            containerColor = MaterialTheme.colorScheme.tertiaryContainer,
            contentColor = MaterialTheme.colorScheme.onTertiaryContainer,
            icon = Icons.Default.Tune
        )
        Verdict.RED -> TriagePresentation(
            title = stringResource(R.string.triage_red_title),
            subtitle = if (triage.reason == TriageSignal.INCOMPATIBLE_PAGE_SIZE) {
                stringResource(R.string.triage_red_page_size_desc)
            } else {
                stringResource(R.string.triage_red_arm32_desc)
            },
            containerColor = MaterialTheme.colorScheme.errorContainer,
            contentColor = MaterialTheme.colorScheme.onErrorContainer,
            icon = Icons.Default.Cancel
        )
        Verdict.NEEDS_USER_INPUT -> TriagePresentation(
            title = stringResource(R.string.triage_needs_input_title),
            subtitle = stringResource(R.string.triage_needs_input_desc),
            containerColor = MaterialTheme.colorScheme.surfaceContainerHighest,
            contentColor = MaterialTheme.colorScheme.onSurface,
            icon = Icons.Default.Warning
        )
    }

    ElevatedCard(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.elevatedCardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainer
        )
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            Surface(
                shape = RoundedCornerShape(12.dp),
                color = presentation.containerColor,
                modifier = Modifier.fillMaxWidth()
            ) {
                Row(
                    modifier = Modifier.padding(14.dp),
                    verticalAlignment = Alignment.Top,
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Icon(
                        imageVector = presentation.icon,
                        contentDescription = null,
                        tint = presentation.contentColor,
                        modifier = Modifier.size(24.dp)
                    )
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = presentation.title,
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold,
                            color = presentation.contentColor,
                            modifier = Modifier.semantics { heading() }
                        )
                        Spacer(modifier = Modifier.height(2.dp))
                        Text(
                            text = presentation.subtitle,
                            style = MaterialTheme.typography.bodySmall,
                            color = presentation.contentColor.copy(alpha = 0.9f),
                            lineHeight = 18.sp
                        )
                    }
                }
            }

            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)

            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 48.dp)
                    .clip(RoundedCornerShape(8.dp))
                    .clickable { isDiagnosticsExpanded = !isDiagnosticsExpanded }
                    .padding(vertical = 4.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(
                    text = stringResource(R.string.diagnostics_header),
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.primary
                )
                IconButton(
                    onClick = { isDiagnosticsExpanded = !isDiagnosticsExpanded },
                    modifier = Modifier.size(48.dp)
                ) {
                    Icon(
                        imageVector = if (isDiagnosticsExpanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                        contentDescription = if (isDiagnosticsExpanded) stringResource(R.string.diagnostics_collapse) else stringResource(R.string.diagnostics_expand),
                        tint = MaterialTheme.colorScheme.primary
                    )
                }
            }

            AnimatedVisibility(visible = isDiagnosticsExpanded) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 4.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    MetadataRow(label = stringResource(R.string.label_package_name), value = apkMeta.packageName.ifEmpty { "N/A" })
                    MetadataRow(label = stringResource(R.string.label_target_sdk), value = stringResource(R.string.target_sdk_value, apkMeta.targetSdk))
                    MetadataRow(label = stringResource(R.string.label_min_sdk), value = stringResource(R.string.min_sdk_value, apkMeta.minSdk))
                    MetadataRow(label = stringResource(R.string.label_device_floor), value = stringResource(R.string.device_floor_value, deviceProfile.installFloor, deviceProfile.osApiLevel))
                    MetadataRow(
                        label = stringResource(R.string.label_install_method),
                        value = triage.installMethod ?: stringResource(R.string.na_transforms_required),
                        isEmphasized = true
                    )
                    MetadataRow(
                        label = stringResource(R.string.label_technical_reason),
                        value = formatTriageReason(triage.reason),
                        isEmphasized = true
                    )

                    if (triage.details.isNotEmpty()) {
                        Surface(
                            shape = RoundedCornerShape(8.dp),
                            color = MaterialTheme.colorScheme.surfaceContainerHighest,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text(
                                text = triage.details,
                                style = MaterialTheme.typography.bodySmall,
                                fontFamily = FontFamily.Monospace,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.padding(10.dp)
                            )
                        }
                    }

                    if (triage.requiredTransforms.isNotEmpty()) {
                        Column(
                            modifier = Modifier.padding(top = 4.dp),
                            verticalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            Text(
                                text = stringResource(R.string.label_required_transforms),
                                style = MaterialTheme.typography.labelMedium,
                                fontWeight = FontWeight.SemiBold
                            )
                            triage.requiredTransforms.forEach { transform ->
                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                                ) {
                                    Icon(
                                        imageVector = Icons.Default.Tune,
                                        contentDescription = null,
                                        modifier = Modifier.size(14.dp),
                                        tint = MaterialTheme.colorScheme.primary
                                    )
                                    Text(
                                        text = transform,
                                        style = MaterialTheme.typography.bodySmall,
                                        fontFamily = FontFamily.Monospace,
                                        color = MaterialTheme.colorScheme.primary
                                    )
                                }
                            }
                        }
                    }

                    if (triage.warnings.isNotEmpty()) {
                        Column(
                            modifier = Modifier.padding(top = 4.dp),
                            verticalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            Text(
                                text = stringResource(R.string.label_warnings),
                                style = MaterialTheme.typography.labelMedium,
                                fontWeight = FontWeight.SemiBold,
                                color = MaterialTheme.colorScheme.tertiary
                            )
                            triage.warnings.forEach { warn ->
                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                                ) {
                                    Icon(
                                        imageVector = Icons.Default.Warning,
                                        contentDescription = null,
                                        modifier = Modifier.size(14.dp),
                                        tint = MaterialTheme.colorScheme.tertiary
                                    )
                                    Text(
                                        text = warn,
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurface
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

fun formatTriageReason(signal: com.apkrevive.core.TriageSignal): String {
    return when (signal) {
        com.apkrevive.core.TriageSignal.RUNNABLE_UNMODIFIED -> "Direct Install Ready"
        com.apkrevive.core.TriageSignal.MODIFICATION_REQUIRED -> "Compatibility Fixes Required"
        com.apkrevive.core.TriageSignal.INCOMPATIBLE_PAGE_SIZE -> "Incompatible 16KB System Memory"
        com.apkrevive.core.TriageSignal.INCOMPATIBLE_DEVICE_ABI -> "Incompatible 32-bit Architecture"
        com.apkrevive.core.TriageSignal.UNRESOLVABLE_SYSTEM_LIBRARY -> "Unsupported Private System Library"
        com.apkrevive.core.TriageSignal.SIGNATURE_VERIFICATION_DETECTED -> "Self-Signature Verification Detected"
        com.apkrevive.core.TriageSignal.EXCEEDS_2GB_LIMIT_FOR_REPACKING -> "Package Exceeds 2GB Limit"
        com.apkrevive.core.TriageSignal.NEEDS_APACHE_HTTP_LEGACY -> "Requires Legacy Apache HTTP Library"
        com.apkrevive.core.TriageSignal.NEEDS_PILLARBOX_FIX -> "Requires Widescreen Display Scaling"
        com.apkrevive.core.TriageSignal.NEEDS_REFRESH_RATE_FIX -> "Requires 60 FPS Physics Cap"
        com.apkrevive.core.TriageSignal.NEEDS_PAGE_SIZE_COMPAT -> "Requires 16KB Page Compatibility"
        com.apkrevive.core.TriageSignal.NEEDS_PAGE_SIZE_COMPAT_ANDROID16 -> "Requires Android 16 Page Compatibility"
        com.apkrevive.core.TriageSignal.NEEDS_HAS_CODE_FLAG -> "Requires Application Code Flag"
        com.apkrevive.core.TriageSignal.SPLIT_APK_UNSUPPORTED -> "Split APK Unsupported"
    }
}

@Composable
fun MetadataRow(label: String, value: String, isEmphasized: Boolean = false) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 2.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodySmall,
            fontWeight = if (isEmphasized) FontWeight.Bold else FontWeight.Normal,
            color = if (isEmphasized) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface,
            fontFamily = if (isEmphasized) FontFamily.Monospace else FontFamily.Default
        )
    }
}

// ---------------------------------------------------------------------------
// 4. Modernizer Feature Toggles Card
// ---------------------------------------------------------------------------
@Composable
fun ModernizerTogglesCard(
    expandAspectRatio: Boolean,
    onExpandAspectRatioChange: (Boolean) -> Unit,
    lock60Hz: Boolean,
    onLock60HzChange: (Boolean) -> Unit,
    expandCutout: Boolean,
    onExpandCutoutChange: (Boolean) -> Unit
) {
    ElevatedCard(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.elevatedCardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainer
        )
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Icon(
                    imageVector = Icons.Default.Tune,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary
                )
                Text(
                    text = stringResource(R.string.toggles_title),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurface,
                    modifier = Modifier.semantics { heading() }
                )
            }

            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)

            ToggleItem(
                title = stringResource(R.string.toggle_aspect_ratio_title),
                description = stringResource(R.string.toggle_aspect_ratio_desc),
                checked = expandAspectRatio,
                onCheckedChange = onExpandAspectRatioChange
            )

            ToggleItem(
                title = stringResource(R.string.toggle_lock_60hz_title),
                description = stringResource(R.string.toggle_lock_60hz_desc),
                checked = lock60Hz,
                onCheckedChange = onLock60HzChange
            )

            ToggleItem(
                title = stringResource(R.string.toggle_cutout_title),
                description = stringResource(R.string.toggle_cutout_desc),
                checked = expandCutout,
                onCheckedChange = onExpandCutoutChange
            )
        }
    }
}

@Composable
fun ToggleItem(
    title: String,
    description: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 48.dp)
            .clip(RoundedCornerShape(8.dp))
            .toggleable(
                value = checked,
                role = Role.Switch,
                onValueChange = onCheckedChange
            )
            .padding(vertical = 8.dp, horizontal = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onSurface
            )
            Text(
                text = description,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        Spacer(modifier = Modifier.width(16.dp))
        Switch(
            checked = checked,
            onCheckedChange = null
        )
    }
}

// ---------------------------------------------------------------------------
// 5. Install Action Card
// ---------------------------------------------------------------------------
@Composable
fun InstallActionCard(
    canInstall: Boolean,
    isInstalling: Boolean,
    isShizukuAuthorized: Boolean,
    isShizukuAvailable: Boolean,
    triageResult: TriageResult?,
    installStatusMessage: String?,
    installSuccess: Boolean?,
    onInstallClick: () -> Unit,
    onRequestPermission: () -> Unit
) {
    ElevatedCard(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.elevatedCardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainer
        )
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            Text(
                text = stringResource(R.string.install_card_title),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onSurface,
                modifier = Modifier.semantics { heading() }
            )

            val buttonText = when {
                !isShizukuAuthorized -> stringResource(R.string.btn_authorize_to_install)
                triageResult?.verdict == Verdict.RED -> stringResource(R.string.btn_cannot_install)
                triageResult?.verdict == Verdict.YELLOW -> stringResource(R.string.btn_apply_fixes_install)
                else -> stringResource(R.string.btn_install_app)
            }

            val isEnabled = when {
                isInstalling -> false
                !isShizukuAuthorized -> isShizukuAvailable
                triageResult?.verdict == Verdict.RED -> false
                else -> canInstall
            }

            Button(
                onClick = {
                    if (!isShizukuAuthorized) {
                        onRequestPermission()
                    } else {
                        onInstallClick()
                    }
                },
                enabled = isEnabled,
                shape = RoundedCornerShape(12.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.primary,
                    disabledContainerColor = MaterialTheme.colorScheme.surfaceContainerHighest
                ),
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 56.dp)
            ) {
                if (isInstalling) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(24.dp),
                        color = MaterialTheme.colorScheme.onPrimary,
                        strokeWidth = 2.5.dp
                    )
                    Spacer(modifier = Modifier.width(12.dp))
                    Text(
                        text = stringResource(R.string.status_installing),
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold
                    )
                } else {
                    Icon(
                        imageVector = if (!isShizukuAuthorized) Icons.Default.Security else Icons.Default.SystemUpdate,
                        contentDescription = null,
                        modifier = Modifier.size(22.dp)
                    )
                    Spacer(modifier = Modifier.width(10.dp))
                    Text(
                        text = buttonText,
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold
                    )
                }
            }

            if (!isShizukuAuthorized) {
                Text(
                    text = stringResource(R.string.status_requires_permission),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error
                )
            } else if (triageResult?.verdict == Verdict.RED) {
                Text(
                    text = stringResource(R.string.status_blocked_abi),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error
                )
            } else if (!canInstall) {
                Text(
                    text = stringResource(R.string.status_sample_selected),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            AnimatedVisibility(visible = installStatusMessage != null) {
                val (containerColor, contentColor, icon) = when (installSuccess) {
                    true -> Triple(
                        MaterialTheme.colorScheme.primaryContainer,
                        MaterialTheme.colorScheme.onPrimaryContainer,
                        Icons.Default.CheckCircle
                    )
                    false -> Triple(
                        MaterialTheme.colorScheme.errorContainer,
                        MaterialTheme.colorScheme.onErrorContainer,
                        Icons.Default.Error
                    )
                    null -> Triple(
                        MaterialTheme.colorScheme.surfaceContainerHighest,
                        MaterialTheme.colorScheme.onSurface,
                        Icons.Default.Info
                    )
                }

                Surface(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(10.dp),
                    color = containerColor
                ) {
                    Row(
                        modifier = Modifier.padding(14.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        Icon(
                            imageVector = icon,
                            contentDescription = null,
                            tint = contentColor,
                            modifier = Modifier.size(20.dp)
                        )
                        Text(
                            text = installStatusMessage ?: "",
                            style = MaterialTheme.typography.bodyMedium,
                            color = contentColor,
                            fontWeight = FontWeight.Medium
                        )
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers & Analysis Logic
// ---------------------------------------------------------------------------
fun getHostDeviceProfile(context: Context? = null): DeviceProfile {
    val pageSize = try {
        android.system.Os.sysconf(android.system.OsConstants._SC_PAGESIZE)
    } catch (_: Throwable) {
        4096L
    }

    val isHighRefresh = try {
        val windowManager = context?.getSystemService(Context.WINDOW_SERVICE) as? android.view.WindowManager
        @Suppress("DEPRECATION")
        val refresh = windowManager?.defaultDisplay?.refreshRate ?: 60f
        refresh > 60f
    } catch (_: Throwable) {
        false
    }

    val installFloor = if (Build.VERSION.SDK_INT >= 34) 24 else 1

    return DeviceProfile(
        osApiLevel = Build.VERSION.SDK_INT,
        installFloor = installFloor,
        supportedAbis = Build.SUPPORTED_ABIS.toList(),
        pageSizeBytes = pageSize,
        isWidescreen = true,
        isHighRefresh = isHighRefresh
    )
}

fun queryFileInfo(context: Context, uri: Uri): Pair<String, Long> {
    var name = "selected_app.apk"
    var size = 0L
    try {
        context.contentResolver.query(uri, null, null, null, null)?.use { cursor ->
            val nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            val sizeIndex = cursor.getColumnIndex(OpenableColumns.SIZE)
            if (cursor.moveToFirst()) {
                if (nameIndex != -1) name = cursor.getString(nameIndex) ?: name
                if (sizeIndex != -1) size = cursor.getLong(sizeIndex)
            }
        }
    } catch (_: Throwable) {}
    return Pair(name, size)
}

suspend fun extractApkInspection(
    context: Context,
    uri: Uri,
    fallbackSize: Long
): Result<ApkInspectionResult> = withContext(Dispatchers.IO) {
    ApkInspector.inspectApk(context, uri, fallbackSize)
}

suspend fun extractApkMetadata(context: Context, uri: Uri, fallbackSize: Long): ApkMetadata? =
    extractApkInspection(context, uri, fallbackSize).getOrNull()?.metadata

fun formatBytes(bytes: Long): String {
    if (bytes <= 0) return "0 B"
    val units = arrayOf("B", "KB", "MB", "GB")
    var digitGroups = (Math.log10(bytes.toDouble()) / Math.log10(1024.0)).toInt()
    if (digitGroups >= units.size) digitGroups = units.size - 1
    val df = String.format("%.2f %s", bytes / Math.pow(1024.0, digitGroups.toDouble()), units[digitGroups])
    return df
}
