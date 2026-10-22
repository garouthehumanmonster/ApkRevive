package com.apkrevive.ui

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.core.content.ContextCompat
import com.apkrevive.installer.InstallResultReceiver
import com.apkrevive.installer.ShizukuPackageInstallerBridge
import rikka.shizuku.Shizuku

class MainActivity : ComponentActivity() {

    private val viewModel: ApkReviveViewModel by viewModels()

    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { _ ->
        // Notification permission handled
    }

    private val permissionListener = Shizuku.OnRequestPermissionResultListener { requestCode, _ ->
        if (requestCode == SHIZUKU_REQUEST_CODE) {
            updateShizukuState()
        }
    }

    private val binderReceivedListener = Shizuku.OnBinderReceivedListener {
        updateShizukuState()
    }

    private val binderDeadListener = Shizuku.OnBinderDeadListener {
        updateShizukuState()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        createNotificationChannel()
        requestNotificationPermission()

        try {
            Shizuku.addRequestPermissionResultListener(permissionListener)
            Shizuku.addBinderReceivedListenerSticky(binderReceivedListener)
            Shizuku.addBinderDeadListener(binderDeadListener)
        } catch (_: Throwable) {}

        updateShizukuState()

        setContent {
            val darkTheme = isSystemInDarkTheme()
            MaterialTheme(
                colorScheme = if (darkTheme) darkColorScheme() else lightColorScheme()
            ) {
                ApkReviveScreen(
                    viewModel = viewModel,
                    onRequestShizukuPermission = {
                        requestShizukuPermission()
                    }
                )
            }
        }
    }

    override fun onResume() {
        super.onResume()
        updateShizukuState()
    }

    override fun onDestroy() {
        super.onDestroy()
        try {
            Shizuku.removeRequestPermissionResultListener(permissionListener)
            Shizuku.removeBinderReceivedListener(binderReceivedListener)
            Shizuku.removeBinderDeadListener(binderDeadListener)
        } catch (_: Throwable) {}
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                InstallResultReceiver.CHANNEL_ID,
                "ApkRevive Installations",
                NotificationManager.IMPORTANCE_DEFAULT
            ).apply {
                description = "Status notifications for app installations"
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager?.createNotificationChannel(channel)
        }
    }

    private fun requestNotificationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }
    }

    private fun updateShizukuState() {
        val available = ShizukuPackageInstallerBridge.isShizukuAvailable()
        val authorized = ShizukuPackageInstallerBridge.isShizukuPermissionGranted()
        viewModel.setShizukuStatus(available = available, authorized = authorized)
    }

    private fun requestShizukuPermission() {
        val state = viewModel.uiState.value
        if (state.isShizukuAvailable && !state.isShizukuAuthorized) {
            ShizukuPackageInstallerBridge.requestShizukuPermission(SHIZUKU_REQUEST_CODE)
        }
    }

    companion object {
        const val SHIZUKU_REQUEST_CODE = 1001
    }
}
