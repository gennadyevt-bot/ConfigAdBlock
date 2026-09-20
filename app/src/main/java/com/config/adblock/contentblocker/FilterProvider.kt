package com.config.adblock.contentblocker

import android.content.ContentProvider
import android.content.ContentValues
import android.content.Context
import android.database.Cursor
import android.net.Uri
import android.os.ParcelFileDescriptor
import java.io.File
import java.io.FileOutputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Content Blocker API (Yandex Browser / Samsung Internet) — доставка
 * cosmetic- и сетевых правил БЕЗ MITM и БЕЗ VPN. Браузер сам читает
 * content://com.config.adblock.contentBlocker.contentProvider/filters.txt
 * (Adblock Plus-формат, включая ## element hiding). Источник — assets.
 */
class FilterProvider : ContentProvider() {

    private lateinit var filtersFile: File

    private fun cbLog(line: String) {
        try {
            val ctx = context ?: return
            val sp = ctx.getSharedPreferences("stats", Context.MODE_PRIVATE)
            val fmt = SimpleDateFormat("HH:mm:ss", Locale.US)
            val cur = sp.getString("log", "") ?: ""
            val entry = fmt.format(Date()) + " " + line + "\n"
            sp.edit().putString("log", (cur + entry).takeLast(1500)).apply()
        } catch (_: Exception) {}
    }

    override fun onCreate(): Boolean {
        val ctx = context ?: return false
        filtersFile = File(ctx.filesDir, "content_blocker_filters.txt")
        try {
            val data = ctx.assets.open("content_blocker_filters.txt").readBytes()
            FileOutputStream(filtersFile).use { it.write(data) }
            val count = String(data).lines().count {
                it.isNotBlank() && !it.trimStart().startsWith("!") && !it.trimStart().startsWith("[")
            }
            cbLog("YANDEX_CB_RULES_READY count=" + count)
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
        try {
            val sp = context?.getSharedPreferences("stats", Context.MODE_PRIVATE)
            if (sp != null) {
                val n = sp.getInt("cb_served", 0) + 1
                sp.edit().putInt("cb_served", n).apply()
                cbLog("YANDEX_CB_PROVIDER_OPEN uri=" + uri.toString().takeLast(40) + " times=" + n)
            }
        } catch (_: Exception) {}
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
