package com.apkrevive.ui

import com.apkrevive.core.ApkMetadata
import com.apkrevive.core.TriageResult

sealed interface ReviveJobState {
    object Idle : ReviveJobState
    object Inspecting : ReviveJobState
    data class ReadyForRevive(
        val report: TriageResult,
        val metadata: ApkMetadata
    ) : ReviveJobState
    data class ExecutingPipeline(
        val step: String,
        val stepIndex: Int,
        val totalSteps: Int,
        val progressFraction: Float
    ) : ReviveJobState
    data class InstallSuccess(
        val packageName: String
    ) : ReviveJobState
    data class InstallFailed(
        val errorCode: Int,
        val humanExplanation: String,
        val remediation: String
    ) : ReviveJobState
    object Cancelled : ReviveJobState
    data class AwaitingInstaller(
        val reason: String,
        val resumeStep: String
    ) : ReviveJobState
}