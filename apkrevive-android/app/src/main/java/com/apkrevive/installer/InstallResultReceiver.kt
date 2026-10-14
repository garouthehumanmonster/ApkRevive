package com.apkrevive.installer

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow

data class InstallEvent(
    val sessionId: Int,
    val status: Int,
    val message: String,
    val isSuccess: Boolean
)

class InstallResultReceiver : BroadcastReceiver() {

    companion object {
        const val TAG = "InstallResultReceiver"
        const val CHANNEL_ID = "apkrevive_install_channel"
        private val _events = MutableSharedFlow<InstallEvent>(replay = 1, extraBufferCapacity = 10)
        val events = _events.asSharedFlow()
    }

    override fun onReceive(context: Context, intent: Intent) {
        val status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)
        val message = intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE) ?: ""
        val sessionId = intent.getIntExtra("SESSION_ID", -1)

        val isSuccess = status == PackageInstaller.STATUS_SUCCESS
        Log.i(TAG, "Session $sessionId install result: status=$status ($message), success=$isSuccess")

        _events.tryEmit(
            InstallEvent(
                sessionId = sessionId,
                status = status,
                message = if (isSuccess) "Installation succeeded!" else "Install failed ($status): $message",
                isSuccess = isSuccess
            )
        )

        postInstallNotification(context, sessionId, isSuccess, status, message)
    }

    private fun postInstallNotification(
        context: Context,
        sessionId: Int,
        isSuccess: Boolean,
        status: Int,
        message: String
    ) {
        try {
            val title = if (isSuccess) "Installation Succeeded" else "Installation Failed"
            val text = if (isSuccess) {
                "The app was installed successfully."
            } else if (message.isNotBlank()) {
                message
            } else {
                "Package installer returned error status $status."
            }

            val notification = NotificationCompat.Builder(context, CHANNEL_ID)
                .setSmallIcon(if (isSuccess) android.R.drawable.stat_sys_download_done else android.R.drawable.stat_notify_error)
                .setContentTitle(title)
                .setContentText(text)
                .setPriority(NotificationCompat.PRIORITY_DEFAULT)
                .setAutoCancel(true)
                .build()

            val notificationManager = NotificationManagerCompat.from(context)
            if (notificationManager.areNotificationsEnabled()) {
                val notificationId = if (sessionId > 0) sessionId else System.currentTimeMillis().toInt()
                notificationManager.notify(notificationId, notification)
            }
        } catch (e: SecurityException) {
            Log.w(TAG, "Notification permission not granted, skipping notification", e)
        } catch (t: Throwable) {
            Log.w(TAG, "Failed to post install notification", t)
        }
    }
}
