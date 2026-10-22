package com.apkrevive.core

import android.content.Context
import android.net.Uri
import android.os.Build
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipFile

data class ApkInspectionResult(
    val metadata: ApkMetadata,
    val appLabel: String?
)

object ApkInspector {

    /**
     * Parses a 64-bit ELF binary and returns the minimum p_align found across PT_LOAD segments.
     * Returns null if no PT_LOAD segments exist, or if the binary is not a 64-bit little-endian ELF.
     */
    fun parseElf64MinLoadAlign(stream: java.io.InputStream): Long? {
        val header = ByteArray(64)
        var readHeader = 0
        while (readHeader < 64) {
            val r = stream.read(header, readHeader, 64 - readHeader)
            if (r == -1) return null
            readHeader += r
        }

        // Magic: 0x7F, 'E', 'L', 'F'
        if (header[0] != 0x7F.toByte() || header[1] != 'E'.code.toByte() ||
            header[2] != 'L'.code.toByte() || header[3] != 'F'.code.toByte()
        ) {
            return null
        }
        if (header[4] != 2.toByte() || header[5] != 1.toByte()) return null

        val buf = ByteBuffer.wrap(header).order(ByteOrder.LITTLE_ENDIAN)
        val ePhoOff = buf.getLong(32)
        val ePhentSize = buf.getShort(54).toInt() and 0xFFFF
        val ePhNum = buf.getShort(56).toInt() and 0xFFFF

        if (ePhoOff < 64L || ePhNum <= 0 || ePhentSize < 56) return null

        // Skip to ePhoOff
        var toSkip = ePhoOff - 64L
        while (toSkip > 0) {
            val skipped = stream.skip(toSkip)
            if (skipped <= 0) {
                if (stream.read() == -1) return null
                toSkip -= 1
            } else {
                toSkip -= skipped
            }
        }

        var minAlign: Long? = null
        val entryBuf = ByteArray(ePhentSize)
        val phByteBuffer = ByteBuffer.wrap(entryBuf).order(ByteOrder.LITTLE_ENDIAN)

        for (i in 0 until ePhNum) {
            var readEntry = 0
            while (readEntry < ePhentSize) {
                val r = stream.read(entryBuf, readEntry, ePhentSize - readEntry)
                if (r == -1) break
                readEntry += r
            }
            if (readEntry < 56) break

            val pType = phByteBuffer.getInt(0)
            if (pType == 1) { // PT_LOAD == 1
                val pAlign = phByteBuffer.getLong(48)
                minAlign = if (minAlign == null) pAlign else minOf(minAlign, pAlign)
            }
        }
        return minAlign
    }

    fun parseElf64MinLoadAlign(bytes: ByteArray): Long? {
        if (bytes.size < 64) return null

        // Magic: 0x7F, 'E', 'L', 'F'
        if (bytes[0] != 0x7F.toByte() ||
            bytes[1] != 'E'.code.toByte() ||
            bytes[2] != 'L'.code.toByte() ||
            bytes[3] != 'F'.code.toByte()
        ) {
            return null
        }

        // EI_CLASS (offset 4) == 2 (64-bit)
        if (bytes[4] != 2.toByte()) {
            return null
        }

        // EI_DATA (offset 5) == 1 (Little-Endian)
        if (bytes[5] != 1.toByte()) {
            return null
        }

        val buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)

        // e_phoff at offset 32 (8 bytes LE)
        val ePhoOff = buffer.getLong(32)
        // e_phentsize at offset 54 (2 bytes LE)
        val ePhentSize = buffer.getShort(54).toInt() and 0xFFFF
        // e_phnum at offset 56 (2 bytes LE)
        val ePhNum = buffer.getShort(56).toInt() and 0xFFFF

        if (ePhoOff <= 0L || ePhNum <= 0 || ePhentSize < 56) {
            return null
        }

        var minAlign: Long? = null

        for (i in 0 until ePhNum) {
            val phOffset = ePhoOff + i.toLong() * ePhentSize.toLong()
            if (phOffset < 0 || phOffset + 56 > bytes.size) {
                break
            }

            val offsetInt = phOffset.toInt()
            val pType = buffer.getInt(offsetInt) // p_type at offset 0 (4 bytes LE)
            if (pType == 1) { // PT_LOAD == 1
                val pAlign = buffer.getLong(offsetInt + 48) // p_align at offset 48 (8 bytes LE)
                minAlign = if (minAlign == null) pAlign else minOf(minAlign, pAlign)
            }
        }

        return minAlign
    }

    /**
     * Scans classes*.dex files within the ZipFile for UTF-8 byte sequences
     * "org/apache/http" or "Lorg/apache/http/".
     */
    fun scanDexForApacheHttp(zip: ZipFile): Boolean {
        val dexRegex = Regex("""classes.*\.dex""")
        val needle1 = "org/apache/http".toByteArray(Charsets.UTF_8)
        val needle2 = "Lorg/apache/http/".toByteArray(Charsets.UTF_8)
        val buffer = ByteArray(8192)
        val overlapSize = 32

        val entries = zip.entries()
        while (entries.hasMoreElements()) {
            val entry = entries.nextElement()
            if (dexRegex.matches(entry.name)) {
                try {
                    zip.getInputStream(entry).use { stream ->
                        var overlapLen = 0
                        while (true) {
                            val bytesRead = stream.read(buffer, overlapLen, buffer.size - overlapLen)
                            if (bytesRead <= 0) break
                            val totalLen = overlapLen + bytesRead
                            if (containsByteSequence(buffer, totalLen, needle1) ||
                                containsByteSequence(buffer, totalLen, needle2)
                            ) {
                                return true
                            }
                            overlapLen = minOf(totalLen, overlapSize)
                            System.arraycopy(buffer, totalLen - overlapLen, buffer, 0, overlapLen)
                        }
                    }
                } catch (_: Throwable) {}
            }
        }
        return false
    }

    private fun containsByteSequence(source: ByteArray, target: ByteArray): Boolean =
        containsByteSequence(source, source.size, target)

    private fun containsByteSequence(source: ByteArray, length: Int, target: ByteArray): Boolean {
        if (target.isEmpty()) return true
        if (length < target.size) return false
        val first = target[0]
        val max = length - target.size
        var i = 0
        while (i <= max) {
            if (source[i] == first) {
                var match = true
                for (j in 1 until target.size) {
                    if (source[i + j] != target[j]) {
                        match = false
                        break
                    }
                }
                if (match) return true
            }
            i++
        }
        return false
    }

    /**
     * Inspects an APK via Context URI, extracting metadata (targetSdk, minSdk, ABIs,
     * 64-bit ELF alignment, DEX Apache HTTP usage, private Bionic greylist libs, isNonResizeable) and app label.
     */
    fun inspectApk(context: Context, uri: Uri, fallbackSize: Long): Result<ApkInspectionResult> {
        val tempFile = File(context.cacheDir, "temp_inspect_${System.currentTimeMillis()}.apk")
        return try {
            val streamOpened = context.contentResolver.openInputStream(uri)?.use { input ->
                tempFile.outputStream().use { output ->
                    input.copyTo(output)
                }
            }
            if (streamOpened == null) {
                return Result.failure(IllegalArgumentException("Failed to open input stream for URI: $uri"))
            }

            val size = if (tempFile.length() > 0) tempFile.length() else fallbackSize
            val pm = context.packageManager
            val pkgInfo = pm.getPackageArchiveInfo(tempFile.absolutePath, 0)
                ?: return Result.failure(IllegalArgumentException("Failed to parse package archive info"))

            val packageName = pkgInfo.packageName ?: "unknown.package"
            val targetSdk = pkgInfo.applicationInfo?.targetSdkVersion ?: 1
            val minSdk = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                pkgInfo.applicationInfo?.minSdkVersion ?: 1
            } else {
                1
            }
            val versionCode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                pkgInfo.longVersionCode
            } else {
                @Suppress("DEPRECATION")
                pkgInfo.versionCode.toLong()
            }

            val appLabel = pkgInfo.applicationInfo?.let { appInfo ->
                try {
                    appInfo.sourceDir = tempFile.absolutePath
                    appInfo.publicSourceDir = tempFile.absolutePath
                    pm.getApplicationLabel(appInfo).toString()
                } catch (_: Throwable) {
                    null
                }
            }

            var hasCode = true
            var usesApacheHttp = false
            val abis = mutableSetOf<String>()
            val privateLibs = mutableSetOf<String>()
            var minElfAlign64: Long? = null

            ZipFile(tempFile).use { zip ->
                hasCode = zip.getEntry("classes.dex") != null

                // Scan DEX for Apache HTTP usage
                usesApacheHttp = scanDexForApacheHttp(zip)

                val entries = zip.entries()
                while (entries.hasMoreElements()) {
                    val entry = entries.nextElement()
                    val name = entry.name

                    // Collect ABIs from lib/<abi>/
                    if (name.startsWith("lib/")) {
                        val parts = name.split("/")
                        if (parts.size >= 3 && parts[1].isNotEmpty()) {
                            abis.add(parts[1])
                        } else if (parts.size == 2 && parts[1].isNotEmpty() && name.endsWith("/")) {
                            abis.add(parts[1].trimEnd('/'))
                        }
                    }

                    // Detect and collect private Bionic greylist libraries
                    if (name.endsWith(".so")) {
                        val soName = name.substringAfterLast('/')
                        if (soName in TriageEvaluator.BIONIC_GREYLIST) {
                            privateLibs.add(soName)
                        }
                    }

                    // For all 64-bit entries (lib/arm64-v8a/*.so and lib/x86_64/*.so),
                    // read up to 65536 bytes (or full bytes for smaller files) and parse parseElf64MinLoadAlign
                    if (name.endsWith(".so") && (name.startsWith("lib/arm64-v8a/") || name.startsWith("lib/x86_64/"))) {
                        try {
                            zip.getInputStream(entry).use { stream ->
                                val align = parseElf64MinLoadAlign(stream)
                                if (align != null) {
                                    minElfAlign64 = if (minElfAlign64 == null) align else minOf(minElfAlign64!!, align)
                                }
                            }
                        } catch (_: Throwable) {}
                    }
                }
            }

            // If targetSdk < 24, set isNonResizeable = true
            val isNonResizeable = targetSdk < 24

            Result.success(
                ApkInspectionResult(
                    metadata = ApkMetadata(
                        packageName = packageName,
                        targetSdk = targetSdk,
                        minSdk = minSdk,
                        versionCode = versionCode,
                        abis = abis.sorted(),
                        elfLoadAlign64bit = minElfAlign64,
                        privateLibs = privateLibs.sorted(),
                        usesApacheHttp = usesApacheHttp,
                        hasCode = hasCode,
                        isNonResizeable = isNonResizeable,
                        sizeBytes = size
                    ),
                    appLabel = appLabel
                )
            )
        } catch (e: Throwable) {
            Result.failure(e)
        } finally {
            tempFile.delete()
        }
    }
}
