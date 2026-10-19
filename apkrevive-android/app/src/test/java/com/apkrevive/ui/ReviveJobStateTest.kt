package com.apkrevive.ui

import com.apkrevive.core.ApkMetadata
import com.apkrevive.core.TriageResult
import com.apkrevive.core.TriageSignal
import com.apkrevive.core.Verdict
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ReviveJobStateTest {

    @Test
    fun testIdleState() {
        val state: ReviveJobState = ReviveJobState.Idle
        assertTrue(state is ReviveJobState.Idle)
    }

    @Test
    fun testInspectingState() {
        val state: ReviveJobState = ReviveJobState.Inspecting
        assertTrue(state is ReviveJobState.Inspecting)
    }

    @Test
    fun testReadyForReviveState() {
        val report = TriageResult(
            verdict = Verdict.GREEN,
            reason = TriageSignal.RUNNABLE_UNMODIFIED,
            installMethod = "DIRECT_INSTALL"
        )
        val meta = ApkMetadata(
            packageName = "com.legacy.app",
            targetSdk = 28
        )
        val state = ReviveJobState.ReadyForRevive(report, meta)

        assertEquals(report, state.report)
        assertEquals(meta, state.metadata)
        assertEquals("com.legacy.app", state.metadata.packageName)
        assertEquals(Verdict.GREEN, state.report.verdict)
    }

    @Test
    fun testExecutingPipelineProgress() {
        val steps = listOf(
            ReviveJobState.ExecutingPipeline("Opening Stream", 0, 4, 0.1f),
            ReviveJobState.ExecutingPipeline("Writing APK", 1, 4, 0.5f),
            ReviveJobState.ExecutingPipeline("Committing Session", 2, 4, 0.8f),
            ReviveJobState.ExecutingPipeline("Awaiting Verification", 3, 4, 0.95f)
        )

        assertEquals(4, steps.size)
        assertEquals("Opening Stream", steps[0].step)
        assertEquals(0, steps[0].stepIndex)
        assertEquals(0.1f, steps[0].progressFraction, 0.001f)

        assertEquals("Writing APK", steps[1].step)
        assertEquals(1, steps[1].stepIndex)
        assertEquals(0.5f, steps[1].progressFraction, 0.001f)

        assertEquals(4, steps[3].totalSteps)
        assertEquals(0.95f, steps[3].progressFraction, 0.001f)
    }

    @Test
    fun testInstallSuccessState() {
        val state = ReviveJobState.InstallSuccess("com.legacy.revived")
        assertEquals("com.legacy.revived", state.packageName)
    }

    @Test
    fun testInstallFailedStateUpdateIncompatible() {
        val state = ReviveJobState.InstallFailed(
            errorCode = -7,
            humanExplanation = "Existing app has a conflicting cryptographic signature.",
            remediation = "Uninstall the existing version first or use the one-tap remediation to uninstall and retry."
        )

        assertEquals(-7, state.errorCode)
        assertEquals("Existing app has a conflicting cryptographic signature.", state.humanExplanation)
        assertEquals("Uninstall the existing version first or use the one-tap remediation to uninstall and retry.", state.remediation)
    }

    @Test
    fun testInstallFailedStateDeprecatedSdk() {
        val state = ReviveJobState.InstallFailed(
            errorCode = -29,
            humanExplanation = "Target SDK below device floor.",
            remediation = "Bypass flag will be used."
        )

        assertEquals(-29, state.errorCode)
        assertEquals("Target SDK below device floor.", state.humanExplanation)
        assertEquals("Bypass flag will be used.", state.remediation)
    }

    @Test
    fun testCancelledState() {
        val state: ReviveJobState = ReviveJobState.Cancelled
        assertTrue(state is ReviveJobState.Cancelled)
    }

    @Test
    fun testAwaitingInstallerState() {
        val state: ReviveJobState = ReviveJobState.AwaitingInstaller(
            reason = "Awaiting package installer session confirmation",
            resumeStep = "COMMIT_SESSION"
        )
        assertTrue(state is ReviveJobState.AwaitingInstaller)
        val awaiting = state as ReviveJobState.AwaitingInstaller
        assertEquals("Awaiting package installer session confirmation", awaiting.reason)
        assertEquals("COMMIT_SESSION", awaiting.resumeStep)
    }

    @Test
    fun testExhaustivePatternMatching() {
        val states: List<ReviveJobState> = listOf(
            ReviveJobState.Idle,
            ReviveJobState.Inspecting,
            ReviveJobState.ReadyForRevive(
                TriageResult(Verdict.GREEN, TriageSignal.RUNNABLE_UNMODIFIED),
                ApkMetadata()
            ),
            ReviveJobState.ExecutingPipeline("Writing APK", 1, 4, 0.5f),
            ReviveJobState.InstallSuccess("com.example"),
            ReviveJobState.InstallFailed(-7, "Conflict", "Retry"),
            ReviveJobState.Cancelled,
            ReviveJobState.AwaitingInstaller("Confirmation required", "COMMIT")
        )

        val tags = states.map {
            when (it) {
                is ReviveJobState.Idle -> "IDLE"
                is ReviveJobState.Inspecting -> "INSPECTING"
                is ReviveJobState.ReadyForRevive -> "READY"
                is ReviveJobState.ExecutingPipeline -> "PIPELINE"
                is ReviveJobState.InstallSuccess -> "SUCCESS"
                is ReviveJobState.InstallFailed -> "FAILED"
                is ReviveJobState.Cancelled -> "CANCELLED"
                is ReviveJobState.AwaitingInstaller -> "AWAITING"
            }
        }

        assertEquals(
            listOf("IDLE", "INSPECTING", "READY", "PIPELINE", "SUCCESS", "FAILED", "CANCELLED", "AWAITING"),
            tags
        )
    }
}