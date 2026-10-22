package com.apkrevive

import com.apkrevive.core.ApkInspector
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

class ApkInspectorTest {

    private fun createSyntheticElf64(
        pAlign: Long,
        pType: Int = 1, // PT_LOAD
        is64Bit: Boolean = true,
        isLittleEndian: Boolean = true,
        magic: ByteArray = byteArrayOf(0x7F, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte())
    ): ByteArray {
        val totalSize = 120
        val bytes = ByteArray(totalSize)
        val buffer = ByteBuffer.wrap(bytes).order(if (isLittleEndian) ByteOrder.LITTLE_ENDIAN else ByteOrder.BIG_ENDIAN)

        // Magic
        System.arraycopy(magic, 0, bytes, 0, minOf(magic.size, 4))

        // Class (offset 4): 2 = 64-bit, 1 = 32-bit
        bytes[4] = if (is64Bit) 2.toByte() else 1.toByte()

        // Data (offset 5): 1 = Little-endian, 2 = Big-endian
        bytes[5] = if (isLittleEndian) 1.toByte() else 2.toByte()

        // Version (offset 6): 1
        bytes[6] = 1.toByte()

        // e_phoff at offset 32 (8 bytes) -> 64L (program headers start right after 64-byte ELF header)
        buffer.putLong(32, 64L)

        // e_phentsize at offset 54 (2 bytes) -> 56 (standard ELF64 program header size)
        buffer.putShort(54, 56.toShort())

        // e_phnum at offset 56 (2 bytes) -> 1 header
        buffer.putShort(56, 1.toShort())

        // Program header 0 starting at offset 64:
        // p_type at offset 64 + 0 (4 bytes)
        buffer.putInt(64, pType)

        // p_flags at offset 64 + 4 (4 bytes)
        buffer.putInt(68, 5) // PF_R | PF_X

        // p_offset at offset 64 + 8 (8 bytes)
        buffer.putLong(72, 0L)

        // p_vaddr at offset 64 + 16 (8 bytes)
        buffer.putLong(80, 0x1000L)

        // p_paddr at offset 64 + 24 (8 bytes)
        buffer.putLong(88, 0x1000L)

        // p_filesz at offset 64 + 32 (8 bytes)
        buffer.putLong(96, 0x1000L)

        // p_memsz at offset 64 + 40 (8 bytes)
        buffer.putLong(104, 0x1000L)

        // p_align at offset 64 + 48 = 112 (8 bytes)
        buffer.putLong(112, pAlign)

        return bytes
    }

    @Test
    fun testParseElf64MinLoadAlign_synthetic4kb() {
        val bytes = createSyntheticElf64(pAlign = 4096L)
        val result = ApkInspector.parseElf64MinLoadAlign(bytes)
        assertEquals(4096L, result)
    }

    @Test
    fun testParseElf64MinLoadAlign_synthetic16kb() {
        val bytes = createSyntheticElf64(pAlign = 16384L)
        val result = ApkInspector.parseElf64MinLoadAlign(bytes)
        assertEquals(16384L, result)
    }

    @Test
    fun testParseElf64MinLoadAlign_nonElfOr32bit() {
        // Non-ELF (ZIP magic)
        val nonElf = byteArrayOf(0x50, 0x4B, 0x03, 0x04)
        assertNull(ApkInspector.parseElf64MinLoadAlign(nonElf))

        // Empty byte array
        assertNull(ApkInspector.parseElf64MinLoadAlign(ByteArray(0)))

        // Truncated header (< 64 bytes)
        assertNull(ApkInspector.parseElf64MinLoadAlign(ByteArray(40)))

        // 32-bit ELF (class == 1)
        val elf32 = createSyntheticElf64(pAlign = 4096L, is64Bit = false)
        assertNull(ApkInspector.parseElf64MinLoadAlign(elf32))

        // Big-endian ELF (data == 2)
        val elfBigEndian = createSyntheticElf64(pAlign = 4096L, isLittleEndian = false)
        assertNull(ApkInspector.parseElf64MinLoadAlign(elfBigEndian))

        // No PT_LOAD segment (e.g. p_type = 2 / PT_DYNAMIC)
        val elfNoPtLoad = createSyntheticElf64(pAlign = 4096L, pType = 2)
        assertNull(ApkInspector.parseElf64MinLoadAlign(elfNoPtLoad))
    }

    @Test
    fun testParseElf64MinLoadAlign_multipleSegmentsReturnsMin() {
        // Test ELF with 2 PT_LOAD segments: one 65536, one 4096 -> should return 4096
        val totalSize = 64 + 56 * 2
        val bytes = ByteArray(totalSize)
        val buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)

        // Magic + 64-bit + LE
        bytes[0] = 0x7F
        bytes[1] = 'E'.code.toByte()
        bytes[2] = 'L'.code.toByte()
        bytes[3] = 'F'.code.toByte()
        bytes[4] = 2 // 64-bit
        bytes[5] = 1 // LE
        bytes[6] = 1

        buffer.putLong(32, 64L) // e_phoff
        buffer.putShort(54, 56.toShort()) // e_phentsize
        buffer.putShort(56, 2.toShort()) // e_phnum = 2

        // Segment 1: PT_LOAD, p_align = 65536L
        buffer.putInt(64, 1)
        buffer.putLong(64 + 48, 65536L)

        // Segment 2: PT_LOAD, p_align = 4096L
        buffer.putInt(64 + 56, 1)
        buffer.putLong(64 + 56 + 48, 4096L)

        val result = ApkInspector.parseElf64MinLoadAlign(bytes)
        assertEquals(4096L, result)
    }

    @Test
    fun testScanDexForApacheHttp_withAndWithoutMatches() {
        val tempZip = File.createTempFile("test_dex", ".zip")
        try {
            // Zip with classes.dex containing "Lorg/apache/http/client/HttpClient;"
            ZipOutputStream(tempZip.outputStream()).use { zos ->
                zos.putNextEntry(ZipEntry("classes.dex"))
                zos.write("Header Lorg/apache/http/client/HttpClient; trailer".toByteArray(Charsets.UTF_8))
                zos.closeEntry()
            }

            ZipFile(tempZip).use { zf ->
                assertTrue(ApkInspector.scanDexForApacheHttp(zf))
            }

            // Zip without Apache HTTP
            ZipOutputStream(tempZip.outputStream()).use { zos ->
                zos.putNextEntry(ZipEntry("classes.dex"))
                zos.write("Clean dex content with okhttp3".toByteArray(Charsets.UTF_8))
                zos.closeEntry()
            }

            ZipFile(tempZip).use { zf ->
                assertFalse(ApkInspector.scanDexForApacheHttp(zf))
            }
        } finally {
            tempZip.delete()
        }
    }
}
