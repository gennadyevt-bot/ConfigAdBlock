package com.config.adblock.contentblocker

import android.content.ContentProvider
import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.database.Cursor
import android.net.Uri
import android.os.ParcelFileDescriptor
import java.io.File
import java.io.FileOutputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Content Blocker API (Yandex Browser / Samsung Internet) — generic + Dzen rules.
 * Universal AdBlock V1: правила собираются из blocklist.txt (~49k доменов) +
 * существующие правила из content_blocker_filters.txt (Dzen cosmetic).
 * Формат Adblock Plus. Новые правила → broadcast ACTION_UPDATE.
 */
class FilterProvider : ContentProvider() {

    private lateinit var filtersFile: File

    private fun cbLog(line: String) {
        try {
            val ctx = context ?: return
            val sp = ctx.getSharedPreferences("stats", Context.MODE_PRIVATE)
            val fmt = SimpleDateFormat("HH:mm:ss", Locale.US)
            val cur = sp.getString("cb_log", "") ?: ""
            val entry = fmt.format(Date()) + " " + line + "\n"
            sp.edit().putString("cb_log", (cur + entry).takeLast(2000)).apply()
        } catch (_: Exception) {}
    }

    private fun isValidDomain(d: String): Boolean {
        if (d.length < 4 || d.length > 253) return false
        if (d == "localhost" || d == "0.0.0.0" || d == "127.0.0.1") return false
        if (d.all { it.isDigit() || it == '.' }) return false // IP
        if (!d.contains(".")) return false
        if (d.startsWith(".") || d.endsWith(".")) return false
        return d.all { it.isLetterOrDigit() || it == '.' || it == '-' }
    }

    override fun onCreate(): Boolean {
        val ctx = context ?: return false
        filtersFile = File(ctx.filesDir, "content_blocker_filters.txt")
        try {
            val network = LinkedHashSet<String>()
            val cosmetic = LinkedHashSet<String>()
            // 1) network rules из blocklist.txt
            ctx.assets.open("blocklist.txt").bufferedReader().useLines { lines ->
                lines.forEach { raw ->
                    var l = raw.trim()
                    if (l.isEmpty() || l.startsWith("#") || l.startsWith("!")) return@forEach
                    if (l.startsWith("0.0.0.0 ") || l.startsWith("127.0.0.1 ")) l = l.substring(l.indexOf(' ') + 1).trim()
                    if (l.startsWith("||")) l = l.removePrefix("||").substringBefore('^').substringBefore('*').substringBefore('/')
                    l = l.removePrefix("www.").lowercase()
                    if (isValidDomain(l)) network.add("||" + l + "^")
                }
            }
            // 2) существующие правила из старого файла (Dzen cosmetic + ABP)
            try {
                ctx.assets.open("dzen_legacy_rules.txt").bufferedReader().useLines { lines ->
                    lines.forEach { raw ->
                        val l = raw.trim()
                        if (l.isEmpty() || l.startsWith("!")) return@forEach
                        if (l.contains("##")) cosmetic.add(l)
                        else if (l.startsWith("||") || l.startsWith("@@")) network.add(l)
                        else if (isValidDomain(l.removePrefix("||").substringBefore('^'))) network.add("||" + l.removePrefix("||").substringBefore('^') + "^")
                    }
                }
            } catch (_: Exception) {}
            // 3) запись файла
            val sb = StringBuilder("[Adblock Plus 2.0]\n")
            network.forEach { sb.append(it).append('\n') }
            cosmetic.forEach { sb.append(it).append('\n') }
            FileOutputStream(filtersFile).use { it.write(sb.toString().toByteArray()) }
            val nN = network.size; val nC = cosmetic.size
            cbLog("YANDEX_CB_RULES_READY network=" + nN + " cosmetic=" + nC + " total=" + (nN + nC))
            // 4) broadcast ACTION_UPDATE
            try {
                val i = Intent("com.samsung.android.sbrowser.contentBlocker.ACTION_UPDATE")
                    .setData(Uri.parse("package:" + ctx.packageName))
                    .addFlags(Intent.FLAG_INCLUDE_STOPPED_PACKAGES)
                ctx.sendBroadcast(i)
                cbLog("YANDEX_CB_UPDATE_SENT")
            } catch (e: Exception) { cbLog("YANDEX_CB_UPDATE_FAIL " + (e.message ?: "")) }
        } catch (e: Exception) { cbLog("YANDEX_CB_ERROR " + (e.message ?: "")) }
        return true
    }

    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor {
        if (!filtersFile.exists()) onCreate()
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
