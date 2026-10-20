package com.apkrevive.installer

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.os.Build
import android.os.DeadObjectException
import android.os.IBinder
import android.os.IInterface
import android.os.ParcelFileDescriptor
import android.os.RemoteException
import android.util.Log
import com.apkrevive.core.ObbValidator
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

    const val INSTALL_FAILED_UPDATE_INCOMPATIBLE: Int = -7
    const val INSTALL_FAILED_DEPRECATED_SDK_VERSION: Int = -29
    const val STATUS_INSTALL_FAILED_DEPRECATED_SDK_VERSION_NAME: String = "INSTALL_FAILED_DEPRECATED_SDK_VERSION"

    const val SHELL_PACKAGE_NAME: String = "com.android.shell"
    const val ACTION_INSTALL_RESULT: String = "com.apkrevive.ACTION_INSTALL_STATUS"

    // Test hook for mock uninstallation in JVM unit tests
    var uninstallExecutor: (suspend (packageName: String) -> Result<Boolean>)? = null

    // Test hook for mock installation in JVM unit tests
    var installExecutor: (suspend (apkStream: InputStream, apkSize: Long, bypassLowTargetSdk: Boolean) -> Result<Int>)? = null

    // Centralized reflection helper test hook
    internal var newProcessMethodResolver: (() -> java.lang.reflect.Method)? = null

    fun invokeShizukuNewProcess(cmd: Array<String>): Process {
        val method = try {
            newProcessMethodResolver?.invoke() ?: Shizuku::class.java.getDeclaredMethod(
                "newProcess",
                Array<String>::class.java,
                Array<String>::class.java,
                String::class.java
            ).apply { isAccessible = true }
        } catch (e: NoSuchMethodException) {
            throw IllegalStateException(
                "Shizuku.newProcess is unavailable in this Shizuku API runtime (dev.rikka.shizuku:api:13.1.5 private method missing). " +
                "Verify R8/ProGuard keep rules or migrate to Shizuku UserService.",
                e
            )
        }
        return method.invoke(null, cmd, null, null) as Process
    }

    data class InstallErrorExplanation(
        val errorCode: Int,
        val humanExplanation: String,
        val remediation: String
    )

    class SessionInstallException(
        val errorCode: Int,
        message: String
    ) : Exception(message)

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
     * Inspects Shizuku binder connectivity and returns the current [ShizukuConnectionState].
     */
    fun checkConnectionState(context: Context? = null): ShizukuConnectionState {
        val available = isShizukuAvailable()
        if (!available) {
            if (context != null) {
                val isInstalled = try {
                    context.packageManager.getPackageInfo("moe.shizuku.privileged.api", 0)
                    true
                } catch (_: PackageManager.NameNotFoundException) {
                    false
                } catch (_: Throwable) {
                    false
                }
                if (!isInstalled) {
                    return ShizukuConnectionState.NotInstalled
                }
            }
            return ShizukuConnectionState.ServiceStopped
        }

        val permissionGranted = isShizukuPermissionGranted()
        return if (permissionGranted) {
            val uid = try { Shizuku.getUid() } catch (_: Throwable) { -1 }
            val isRoot = (uid == 0)
            val binderVersion = try { Shizuku.getVersion() } catch (_: Throwable) { 0 }
            ShizukuConnectionState.Connected(
                uid = uid,
                isRootPrivilege = isRoot,
                binderVersion = binderVersion
            )
        } else {
            val rationale = try {
                Shizuku.shouldShowRequestPermissionRationale()
            } catch (_: Throwable) {
                false
            }
            ShizukuConnectionState.PermissionDenied(shouldShowRationale = rationale)
        }
    }

    /**
     * Parses PackageInstaller session failure codes into human-readable explanations and remediations.
     */
    fun parseInstallError(errorCode: Int, rawMessage: String? = null): InstallErrorExplanation {
        val msg = rawMessage ?: ""
        return when {
            errorCode == INSTALL_FAILED_UPDATE_INCOMPATIBLE ||
            msg.contains("INSTALL_FAILED_UPDATE_INCOMPATIBLE", ignoreCase = true) ||
            msg.contains("signatures do not match", ignoreCase = true) ||
            msg.contains("conflicting signature", ignoreCase = true) -> {
                InstallErrorExplanation(
                    errorCode = INSTALL_FAILED_UPDATE_INCOMPATIBLE,
                    humanExplanation = "Existing app has a conflicting cryptographic signature.",
                    remediation = "Uninstall the existing version first or use the one-tap remediation to uninstall and retry."
                )
            }
            errorCode == INSTALL_FAILED_DEPRECATED_SDK_VERSION ||
            msg.contains(STATUS_INSTALL_FAILED_DEPRECATED_SDK_VERSION_NAME, ignoreCase = true) ||
            msg.contains("Target SDK below", ignoreCase = true) -> {
                InstallErrorExplanation(
                    errorCode = INSTALL_FAILED_DEPRECATED_SDK_VERSION,
                    humanExplanation = "Target SDK below device floor.",
                    remediation = "App targets older Android version than platform minimum. Shizuku bypass flag required."
                )
            }
            errorCode == -16 || errorCode == -113 ||
            msg.contains("NO_MATCHING_ABIS", ignoreCase = true) ||
            msg.contains("CPU_ABI_INCOMPATIBLE", ignoreCase = true) -> {
                InstallErrorExplanation(
                    errorCode = errorCode,
                    humanExplanation = "The app's native code is incompatible with this device's processor architecture.",
                    remediation = "Device architecture is not supported by this APK."
                )
            }
            errorCode == -4 || msg.contains("INSUFFICIENT_STORAGE", ignoreCase = true) -> {
                InstallErrorExplanation(
                    errorCode = errorCode,
                    humanExplanation = "Device storage is insufficient to complete installation.",
                    remediation = "Free up device storage space and retry."
                )
            }
            errorCode == -25 || msg.contains("VERSION_DOWNGRADE", ignoreCase = true) -> {
                InstallErrorExplanation(
                    errorCode = errorCode,
                    humanExplanation = "Cannot install an older version over a newer version.",
                    remediation = "Uninstall the current version before installing this older release."
                )
            }
            else -> {
                InstallErrorExplanation(
                    errorCode = errorCode,
                    humanExplanation = if (msg.isNotBlank()) msg else "Package installer returned error code $errorCode.",
                    remediation = "Verify APK compatibility or inspect device logs for additional details."
                )
            }
        }
    }

    /**
     * Uninstalls a package cleanly using Shizuku privileged shell execution.
     */
    suspend fun uninstallPackage(context: Context? = null, packageName: String): Result<Boolean> {
        uninstallExecutor?.let { return it.invoke(packageName) }

        return withContext(Dispatchers.IO) {
            if (!isShizukuPermissionGranted()) {
                return@withContext Result.failure(
                    IllegalStateException("Shizuku is not running or permission is not granted.")
                )
            }

            try {
                val process = invokeShizukuNewProcess(arrayOf("pm", "uninstall", packageName))
                val exitCode = process.waitFor()
                val output = process.inputStream.bufferedReader().use { it.readText() }.trim()
                val errorOutput = process.errorStream.bufferedReader().use { it.readText() }.trim()

                if (exitCode == 0 && (output.contains("Success", ignoreCase = true) || output.isEmpty())) {
                    Result.success(true)
                } else {
                    val err = if (errorOutput.isNotBlank()) errorOutput else output
                    Result.failure(Exception("Uninstall failed (exit $exitCode): $err"))
                }
            } catch (t: Throwable) {
                Log.e(TAG, "Failed to uninstall package $packageName", t)
                Result.failure(t)
            }
        }
    }

    fun isBypassLowTargetSdkSupported(sdkInt: Int = Build.VERSION.SDK_INT): Boolean {
        return sdkInt >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE
    }

    /**
     * Installs an APK using Shizuku privileged shell execution via 'pm install'.
     */
    suspend fun installApkViaShell(
        apkStream: InputStream,
        apkSize: Long,
        bypassLowTargetSdk: Boolean = true,
        onProgress: (step: String, stepIndex: Int, totalSteps: Int, progressFraction: Float) -> Unit = { _, _, _, _ -> }
    ): Result<Boolean> = withContext(Dispatchers.IO) {
        if (!isShizukuPermissionGranted()) {
            return@withContext Result.failure(
                IllegalStateException("Shizuku is not running or permission is not granted.")
            )
        }

        var process: Process? = null
        try {
            val cmd = mutableListOf("pm", "install")
            if (apkSize > 0) {
                cmd.add("-S")
                cmd.add(apkSize.toString())
            }
            if (bypassLowTargetSdk && isBypassLowTargetSdkSupported()) {
                cmd.add("--bypass-low-target-sdk-block")
            }

            val proc = invokeShizukuNewProcess(cmd.toTypedArray())
            process = proc

            onProgress("Writing APK", 1, 4, 0.35f)
            proc.outputStream.use { out ->
                val buffer = ByteArray(65536)
                var bytesRead: Int
                var totalRead = 0L
                while (apkStream.read(buffer).also { bytesRead = it } != -1) {
                    out.write(buffer, 0, bytesRead)
                    totalRead += bytesRead
                    if (apkSize > 0) {
                        val fraction = 0.35f + 0.4f * (totalRead.toFloat() / apkSize.toFloat()).coerceIn(0f, 1f)
                        onProgress("Writing APK", 1, 4, fraction)
                    }
                }
                out.flush()
            }

            onProgress("Committing Installation", 2, 4, 0.8f)
            val exitCode = proc.waitFor()
            val output = proc.inputStream.bufferedReader().use { it.readText() }.trim()
            val errorOutput = proc.errorStream.bufferedReader().use { it.readText() }.trim()

            if (exitCode == 0 && output.contains("Success", ignoreCase = true)) {
                onProgress("Installation Complete", 4, 4, 1.0f)
                Result.success(true)
            } else {
                val err = if (errorOutput.isNotBlank()) errorOutput else output
                Result.failure(Exception("Shell install failed (exit $exitCode): $err"))
            }
        } catch (t: Throwable) {
            Log.e(TAG, "Failed to install APK via shell", t)
            Result.failure(t)
        } finally {
            try {
                process?.destroy()
            } catch (_: Throwable) {}
        }
    }

    /**
     * Pushes an OBB expansion file to /storage/emulated/<userId>/Android/obb/<targetPackage>/ using Shizuku privileged shell.
     * Bypasses Android 11+ scoped storage isolation restrictions on /Android/obb/.
     */
    suspend fun pushObbViaShell(
        obbStream: InputStream,
        targetPackage: String,
        obbFilename: String,
        expectedSize: Long = -1L,
        userId: Int = 0,
        currentApkVersion: Long = 0L
    ): Result<Boolean> = withContext(Dispatchers.IO) {
        val validation = ObbValidator.validateObbDelivery(
            obbFilename = obbFilename,
            targetPackage = targetPackage,
            currentApkVersion = currentApkVersion,
            userId = userId
        )
        if (!validation.isValid) {
            return@withContext Result.failure(
                IllegalArgumentException("Invalid OBB filename: ${validation.reason}")
            )
        }

        if (expectedSize <= 0L) {
            return@withContext Result.failure(
                IllegalArgumentException("expectedSize must be positive: $expectedSize")
            )
        }

        if (!isShizukuPermissionGranted()) {
            return@withContext Result.failure(
                IllegalStateException("Shizuku is not running or permission is not granted.")
            )
        }

        val targetDir = ObbValidator.resolveObbDirectory(targetPackage, userId)
        val partPath = "$targetDir/$obbFilename.part"
        val finalPath = "$targetDir/$obbFilename"

        var writeProcess: Process? = null
        var isSuccess = false
        try {
            val writeCmd = arrayOf("sh", "-c", "mkdir -p \"$1\" && cat > \"$2\"", "sh", targetDir, partPath)
            val proc = invokeShizukuNewProcess(writeCmd)
            writeProcess = proc

            var totalBytesWritten = 0L
            proc.outputStream.use { out ->
                val buffer = ByteArray(65536)
                var bytesRead: Int
                while (obbStream.read(buffer).also { bytesRead = it } != -1) {
                    out.write(buffer, 0, bytesRead)
                    totalBytesWritten += bytesRead
                }
                out.flush()
            }

            val writeExitCode = proc.waitFor()
            val writeErrorOutput = proc.errorStream.bufferedReader().use { it.readText() }.trim()

            if (writeExitCode != 0) {
                return@withContext Result.failure(
                    Exception("Failed to write OBB part file to $partPath (exit $writeExitCode): $writeErrorOutput")
                )
            }

            if (totalBytesWritten != expectedSize) {
                return@withContext Result.failure(
                    IllegalStateException("OBB stream size mismatch: wrote $totalBytesWritten bytes, expected $expectedSize")
                )
            }

            // Verify on-device .part size before mv
            val sizeCmd = arrayOf("sh", "-c", "wc -c < \"$1\"", "sh", partPath)
            val sizeProc = invokeShizukuNewProcess(sizeCmd)
            val sizeExitCode = sizeProc.waitFor()
            val sizeOutput = sizeProc.inputStream.bufferedReader().use { it.readText() }.trim()
            val onDeviceSize = sizeOutput.toLongOrNull() ?: -1L

            if (sizeExitCode != 0 || onDeviceSize != expectedSize) {
                return@withContext Result.failure(
                    IllegalStateException("OBB on-device size mismatch: on-device $onDeviceSize != expected $expectedSize (exit $sizeExitCode)")
                )
            }

            val mvCmd = arrayOf("sh", "-c", "mv -f \"$1\" \"$2\"", "sh", partPath, finalPath)
            val mvProc = invokeShizukuNewProcess(mvCmd)
            val mvExitCode = mvProc.waitFor()
            val mvErrorOutput = mvProc.errorStream.bufferedReader().use { it.readText() }.trim()

            if (mvExitCode != 0) {
                return@withContext Result.failure(
                    Exception("Failed to move OBB part file to $finalPath (exit $mvExitCode): $mvErrorOutput")
                )
            }

            isSuccess = true
            Result.success(true)
        } catch (t: Throwable) {
            Log.e(TAG, "Failed pushing OBB via shell", t)
            Result.failure(t)
        } finally {
            try {
                writeProcess?.destroy()
            } catch (_: Throwable) {}
            if (!isSuccess) {
                try {
                    val rmCmd = arrayOf("sh", "-c", "rm -f \"$1\"", "sh", partPath)
                    val rmProc = invokeShizukuNewProcess(rmCmd)
                    rmProc.waitFor()
                } catch (cleanupEx: Throwable) {
                    Log.w(TAG, "Failed to clean up OBB part file: $partPath", cleanupEx)
                }
            }
        }
    }

    /**
     * Reflectively sets params.installFlags |= 0x01000000 (INSTALL_BYPASS_LOW_TARGET_SDK_BLOCK).
     * Accepts Any to enable clean unit testing on JVM without Android framework stubs.
     * Verifies constant against PackageManager or checks API >= 34 to avoid colliding with
     * future/OEM flags on API 31-33.
     */
    fun applyBypassLowTargetSdkFlag(params: Any, sdkInt: Int = Build.VERSION.SDK_INT): Boolean {
        val flagValue = try {
            val pmClass = Class.forName("android.content.pm.PackageManager")
            val constField = pmClass.getField("INSTALL_BYPASS_LOW_TARGET_SDK_BLOCK")
            constField.getInt(null)
        } catch (_: Throwable) {
            null
        }

        val effectiveFlag = flagValue ?: if (sdkInt >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            INSTALL_BYPASS_LOW_TARGET_SDK_BLOCK
        } else if (sdkInt == 0) {
            // JVM unit test execution fallback
            INSTALL_BYPASS_LOW_TARGET_SDK_BLOCK
        } else {
            Log.w(TAG, "device too old / flag unsupported: API $sdkInt < 34 lacks INSTALL_BYPASS_LOW_TARGET_SDK_BLOCK")
            return false
        }

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
                field.setInt(params, current or effectiveFlag)
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
     * Installs an APK using Shizuku privileged shell session with progress callbacks and DeadObject protection.
     */
    suspend fun installApk(
        context: Context,
        apkStream: InputStream,
        apkSize: Long,
        bypassLowTargetSdk: Boolean = true,
        onProgress: (step: String, stepIndex: Int, totalSteps: Int, progressFraction: Float) -> Unit = { _, _, _, _ -> }
    ): Result<Int> {
        installExecutor?.let { return it.invoke(apkStream, apkSize, bypassLowTargetSdk) }

        return withContext(Dispatchers.IO) {
            var sessionId = -1
            var session: Any? = null
            var iPackageInstaller: Any? = null

            try {
                if (!isShizukuPermissionGranted()) {
                    return@withContext Result.failure(
                        IllegalStateException("Shizuku is not running or permission is not granted.")
                    )
                }

                onProgress("Opening Stream", 0, 4, 0.1f)

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
                if (bypassLowTargetSdk && isBypassLowTargetSdkSupported()) {
                    applyBypassLowTargetSdkFlag(params)
                }

                // 4. Resolve createSession signature
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
                onProgress("Writing APK", 1, 4, 0.35f)
                val openWriteMethod = session.javaClass.getMethod(
                    "openWrite",
                    String::class.java,
                    Long::class.javaPrimitiveType,
                    Long::class.javaPrimitiveType
                )
                val pfd = openWriteMethod.invoke(session, "package", 0L, apkSize) as ParcelFileDescriptor

                ParcelFileDescriptor.AutoCloseOutputStream(pfd).use { out ->
                    val buffer = ByteArray(65536)
                    var bytesRead: Int
                    var totalRead = 0L
                    while (apkStream.read(buffer).also { bytesRead = it } != -1) {
                        out.write(buffer, 0, bytesRead)
                        totalRead += bytesRead
                        if (apkSize > 0) {
                            val fraction = 0.35f + 0.4f * (totalRead.toFloat() / apkSize.toFloat()).coerceIn(0f, 1f)
                            onProgress("Writing APK", 1, 4, fraction)
                        }
                    }
                    out.flush()
                }

                // 7. Commit session with IntentSender
                onProgress("Committing Session", 2, 4, 0.8f)
                val intent = Intent(context, InstallResultReceiver::class.java).apply {
                    action = ACTION_INSTALL_RESULT
                    putExtra("SESSION_ID", sessionId)
                }
                // API 31+ (Android 12 S) requires explicit mutability on PendingIntents.
                // FLAG_MUTABLE is mandatory here because the system PackageInstaller service
                // needs to fill in EXTRA_STATUS and EXTRA_STATUS_MESSAGE extras into the
                // returned Intent before dispatching to InstallResultReceiver.
                // On API < 31, FLAG_UPDATE_CURRENT is used without FLAG_MUTABLE.
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

                // 8. Await verification
                onProgress("Awaiting Verification", 3, 4, 0.95f)
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
                    Result.failure(SessionInstallException(event.errorCode, event.message))
                }
            } catch (t: Throwable) {
                Log.e(TAG, "Shizuku install failed, performing mandatory cleanup", t)
                abandonSessionSafely(session, iPackageInstaller, sessionId)
                Result.failure(t)
            }
        }
    }

    fun invokeCreateSession(
        iPackageInstaller: Any,
        params: PackageInstaller.SessionParams,
        installerPackageName: String,
        userId: Int
    ): Int {
        val methods = iPackageInstaller.javaClass.methods.filter { it.name == "createSession" }

        val fourArgMethod = methods.firstOrNull { it.parameterTypes.size == 4 }
        if (fourArgMethod != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            return fourArgMethod.invoke(iPackageInstaller, params, installerPackageName, null, userId) as Int
        }

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

    fun abandonSessionSafely(session: Any?, iPackageInstaller: Any?, sessionId: Int) {
        try {
            if (session != null) {
                val abandonMethod = session.javaClass.methods.firstOrNull { it.name == "abandon" && it.parameterTypes.isEmpty() }
                abandonMethod?.invoke(session)
            }
        } catch (e: Throwable) {
            val cause = e.cause ?: e
            if (cause !is DeadObjectException && cause !is RemoteException &&
                cause !is SecurityException && cause !is IllegalStateException
            ) {
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
            if (cause !is DeadObjectException && cause !is RemoteException &&
                cause !is SecurityException && cause !is IllegalStateException
            ) {
                Log.w(TAG, "Failed abandoning session on IPackageInstaller", e)
            }
        }
    }
}