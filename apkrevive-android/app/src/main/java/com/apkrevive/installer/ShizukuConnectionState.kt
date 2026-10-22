package com.apkrevive.installer

sealed interface ShizukuConnectionState {
    object NotInstalled : ShizukuConnectionState
    object ServiceStopped : ShizukuConnectionState
    data class PermissionDenied(val shouldShowRationale: Boolean = false) : ShizukuConnectionState
    data class Connected(
        val uid: Int,
        val isRootPrivilege: Boolean,
        val binderVersion: Int
    ) : ShizukuConnectionState
}