package com.apkrevive.installer

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.os.Build
import android.os.IBinder
import android.os.IInterface
import android.os.ParcelFileDescriptor
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import rikka.shizuku.Shizuku
import rikka.shizuku.ShizukuBinderWrapper
import rikka.shizuku.SystemServiceHelper
import java.io.InputStream
import java.util.concurrent.TimeoutException

object ShizukuPackageInstallerBridge {

    private const val TAG = "ApkReviveBridge"

    // Hidden API constant introduced in Android 14 (API 34)
    // Framework constant: PackageManager.INSTALL_BYPASS_LOW_TARGET_SDK_BLOCK
    const val INSTALL_BYPASS_LOW_TARGET_SDK_BLOCK: Int = 0x01000000

    const val SHELL_PACKAGE_NAME: String = "com.android.shell"
    const val ACTION_INSTALL_RESULT: String = "com.apkrevive.ACTION_INSTALL_STATUS"

    fun isShizukuAvailable(): Boolean {
        return try {
            Shizuku.pingBinder()
        } catch (e: Throwable) {
            Log.w(TAG, "Shizuku not reachable", e)
            false
        }
    }

    fun isShizukuPermissionGranted(): Boolean {
        return try {
            if (!isShizukuAvailable()) return false
            Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED
        } catch (e: Throwable) {
            Log.w(TAG, "Failed checking Shizuku permission", e)
            false
        }
    }

    fun requestShizukuPermission(requestCode: Int = 1001) {
        if (isShizukuAvailable() && !isShizukuPermissionGranted()) {
            Shizuku.requestPermission(requestCode)
        }
    }

    /**
     * Reflectively sets params.installFlags |= 0x01000000 (INSTALL_BYPASS_LOW_TARGET_SDK_BLOCK).
     * Accepts Any to enable clean unit testing on JVM without Android framework stubs.
     */
    fun applyBypassLowTargetSdkFlag(params: Any): Boolean {
        return try {
            var clazz: Class<*>? = params.javaClass
            var field = clazz?.declaredFields?.firstOrNull { it.name == "installFlags" }
            while (field == null && clazz != null && clazz != Any::class.java) {
                clazz = clazz.superclass
                field = clazz?.declaredFields?.firstOrNull { it.name == "installFlags" }
            }
            if (field != null) {
                field.isAccessible = true
                val current = field.getInt(params)
                field.setInt(params, current or INSTALL_BYPASS_LOW_TARGET_SDK_BLOCK)
                true
            } else {
                Log.w(TAG, "Field installFlags not found on ${params.javaClass.name}")
                false
            }
        } catch (e: Throwable) {
            Log.e(TAG, "Failed to apply INSTALL_BYPASS_LOW_TARGET_SDK_BLOCK reflectively", e)
            false
        }
    }

    /**
     * Installs an APK using Shizuku privileged shell session.
     */
    suspend fun installApk(
        context: Context,
        apkStream: InputStream,
        apkSize: Long,
        bypassLowTargetSdk: Boolean = true
    ): Result<Int> = withContext(Dispatchers.IO) {
        var sessionId = -1
        var session: Any? = null
        var iPackageInstaller: Any? = null

        try {
            if (!isShizukuPermissionGranted()) {
                return@withContext Result.failure(
                    IllegalStateException("Shizuku is not running or permission is not granted.")
                )
            }

            // 1. Get IPackageManager wrapped in ShizukuBinderWrapper
            val packageServiceBinder = SystemServiceHelper.getSystemService("package")
                ?: return@withContext Result.failure(IllegalStateException("Unable to acquire 'package' service"))
            val wrappedPackageService = ShizukuBinderWrapper(packageServiceBinder)

            val ipmStubClass = Class.forName("android.content.pm.IPackageManager\$Stub")
            val ipmAsInterface = ipmStubClass.getMethod("asInterface", IBinder::class.java)
            val iPackageManager = ipmAsInterface.invoke(null, wrappedPackageService)

            // 2. Get IPackageInstaller and wrap in ShizukuBinderWrapper
            val getInstallerMethod = iPackageManager.javaClass.getMethod("getPackageInstaller")
            val rawInstaller = getInstallerMethod.invoke(iPackageManager) as IInterface
            val wrappedInstallerBinder = ShizukuBinderWrapper(rawInstaller.asBinder())

            val ipiStubClass = Class.forName("android.content.pm.IPackageInstaller\$Stub")
            val ipiAsInterface = ipiStubClass.getMethod("asInterface", IBinder::class.java)
            iPackageInstaller = ipiAsInterface.invoke(null, wrappedInstallerBinder)

            // 3. Create SessionParams
            val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL)
            if (apkSize > 0) {
                params.setSize(apkSize)
            }
            if (bypassLowTargetSdk) {
                applyBypassLowTargetSdkFlag(params)
            }

            // 4. Resolve createSession signature:
            // API 30: createSession(SessionParams, String installerPackageName, int userId)
            // API 31+: createSession(SessionParams, String installerPackageName, String callingFeatureId, int userId)
            sessionId = invokeCreateSession(iPackageInstaller, params, SHELL_PACKAGE_NAME, 0)

            if (sessionId <= 0) {
                return@withContext Result.failure(
                    IllegalStateException("Invalid sessionId received: $sessionId")
                )
            }

            // 5. Open Session
            val openSessionMethod = iPackageInstaller.javaClass.getMethod(
                "openSession",
                Int::class.javaPrimitiveType
            )
            val rawSession = openSessionMethod.invoke(iPackageInstaller, sessionId) as IInterface
            val wrappedSessionBinder = ShizukuBinderWrapper(rawSession.asBinder())

            val sessionStubClass = Class.forName("android.content.pm.IPackageInstallerSession\$Stub")
            val sessionAsInterface = sessionStubClass.getMethod("asInterface", IBinder::class.java)
            session = sessionAsInterface.invoke(null, wrappedSessionBinder)

            // 6. Stream APK bytes into session.openWrite("package", 0, size)
            val openWriteMethod = session.javaClass.getMethod(
                "openWrite",
                String::class.java,
                Long::class.javaPrimitiveType,
                Long::class.javaPrimitiveType
            )
            val pfd = openWriteMethod.invoke(session, "package", 0L, apkSize) as ParcelFileDescriptor

            ParcelFileDescriptor.AutoCloseOutputStream(pfd).use { out ->
                apkStream.copyTo(out)
                out.flush()
            }

            // 7. Commit session with IntentSender
            val intent = Intent(context, InstallResultReceiver::class.java).apply {
                action = ACTION_INSTALL_RESULT
                putExtra("SESSION_ID", sessionId)
            }
            val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE
            } else {
                PendingIntent.FLAG_UPDATE_CURRENT
            }
            val pendingIntent = PendingIntent.getBroadcast(
                context,
                sessionId,
                intent,
                flags
            )

            invokeCommitSession(session, pendingIntent.intentSender)

            // Await terminal broadcast from InstallResultReceiver with 60s timeout
            val event = withTimeoutOrNull(60_000L) {
                InstallResultReceiver.events.first { it.sessionId == sessionId }
            }

            if (event == null) {
                abandonSessionSafely(session, iPackageInstaller, sessionId)
                return@withContext Result.failure(
                    TimeoutException("Installation timed out waiting for PackageInstaller confirmation.")
                )
            }

            if (event.isSuccess) {
                Result.success(sessionId)
            } else {
                abandonSessionSafely(session, iPackageInstaller, sessionId)
                Result.failure(Exception(event.message))
            }
        } catch (t: Throwable) {
            Log.e(TAG, "Shizuku install failed, performing mandatory cleanup", t)
            abandonSessionSafely(session, iPackageInstaller, sessionId)
            Result.failure(t)
        }
    }

    fun invokeCreateSession(
        iPackageInstaller: Any,
        params: PackageInstaller.SessionParams,
        installerPackageName: String,
        userId: Int
    ): Int {
        val methods = iPackageInstaller.javaClass.methods.filter { it.name == "createSession" }

        // Attempt 4-arg signature (API 31+): (SessionParams, String, String, int)
        val fourArgMethod = methods.firstOrNull { it.parameterTypes.size == 4 }
        if (fourArgMethod != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            return fourArgMethod.invoke(iPackageInstaller, params, installerPackageName, null, userId) as Int
        }

        // Attempt 3-arg signature (API 30): (SessionParams, String, int)
        val threeArgMethod = methods.firstOrNull { it.parameterTypes.size == 3 }
        if (threeArgMethod != null) {
            return threeArgMethod.invoke(iPackageInstaller, params, installerPackageName, userId) as Int
        }

        if (fourArgMethod != null) {
            return fourArgMethod.invoke(iPackageInstaller, params, installerPackageName, null, userId) as Int
        }

        throw NoSuchMethodException("No matching createSession method found on ${iPackageInstaller.javaClass.name}")
    }

    private fun invokeCommitSession(session: Any, statusReceiver: Any) {
        val methods = session.javaClass.methods.filter { it.name == "commit" }
        val twoArg = methods.firstOrNull { it.parameterTypes.size == 2 }
        if (twoArg != null) {
            twoArg.invoke(session, statusReceiver, false)
            return
        }

        val oneArg = methods.firstOrNull { it.parameterTypes.size == 1 }
        if (oneArg != null) {
            oneArg.invoke(session, statusReceiver)
            return
        }

        throw NoSuchMethodException("No matching commit method found on ${session.javaClass.name}")
    }

    private fun abandonSessionSafely(session: Any?, iPackageInstaller: Any?, sessionId: Int) {
        try {
            if (session != null) {
                val abandonMethod = session.javaClass.methods.firstOrNull { it.name == "abandon" && it.parameterTypes.isEmpty() }
                abandonMethod?.invoke(session)
            }
        } catch (e: Throwable) {
            val cause = e.cause ?: e
            if (cause !is SecurityException && cause !is IllegalStateException) {
                Log.w(TAG, "Failed abandoning session on IPackageInstallerSession", e)
            }
        }

        try {
            if (iPackageInstaller != null && sessionId > 0) {
                val abandonSessionMethod = iPackageInstaller.javaClass.methods.firstOrNull {
                    it.name == "abandonSession" && it.parameterTypes.size == 1
                }
                abandonSessionMethod?.invoke(iPackageInstaller, sessionId)
            }
        } catch (e: Throwable) {
            val cause = e.cause ?: e
            if (cause !is SecurityException && cause !is IllegalStateException) {
                Log.w(TAG, "Failed abandoning session on IPackageInstaller", e)
            }
        }
    }
}
