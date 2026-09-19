package com.config.adblock.contentblocker

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.net.Uri
import android.os.ParcelFileDescriptor
import java.io.File
import java.io.FileOutputStream

/**
 * Content Blocker API (Samsung Internet / Yandex Browser) — канал доставки
 * cosmetic- и сетевых правил БЕЗ MITM и БЕЗ fake-IP. Браузер сам читает
 * content://com.config.adblock.contentBlocker.contentProvider/filters.txt
 * (Adblock Plus-формат, включая ## element hiding). Источник — assets.
 */
class FilterProvider : ContentProvider() {

    private lateinit var filtersFile: File

    override fun onCreate(): Boolean {
        val ctx = context ?: return false
        filtersFile = File(ctx.filesDir, "content_blocker_filters.txt")
        try {
            val data = ctx.assets.open("content_blocker_filters.txt").readBytes()
            FileOutputStream(filtersFile).use { it.write(data) }
        } catch (_: Exception) {}
        return true
    }

    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor {
        if (!filtersFile.exists()) {
            try {
                val data = context?.assets?.open("content_blocker_filters.txt")?.readBytes()
                if (data != null) {
                    FileOutputStream(filtersFile).use { it.write(data) }
                }
            } catch (_: Exception) {}
        }
        return ParcelFileDescriptor.open(filtersFile, ParcelFileDescriptor.MODE_READ_ONLY)
    }

    override fun getType(uri: Uri): String = "text/plain"
    override fun query(uri: Uri, projection: Array<String>?, selection: String?,
                       selectionArgs: Array<String>?, sortOrder: String?): Cursor? = null
    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun update(uri: Uri, values: ContentValues?, selection: String?,
                        selectionArgs: Array<String>?): Int = 0
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<String>?): Int = 0
}
