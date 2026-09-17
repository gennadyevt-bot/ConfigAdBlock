package com.config.adblock

import android.Manifest
import android.content.ContentValues
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.os.Handler
import android.os.Looper
import android.provider.MediaStore
import android.provider.Settings
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.button.MaterialButton
import com.google.android.material.checkbox.MaterialCheckBox
import java.io.File
import kotlin.concurrent.thread

class MainActivity : AppCompatActivity() {

    private lateinit var prefs: android.content.SharedPreferences
    private val handler = Handler(Looper.getMainLooper())
    private val ticker = object : Runnable {
        override fun run() { updateUi(); handler.postDelayed(this, 1000) }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        prefs = getSharedPreferences("stats", MODE_PRIVATE)
        val ver = try { packageManager.getPackageInfo(packageName, 0).versionName } catch (e: Exception) { "?" }
        findViewById<TextView>(R.id.tvVersion).text = "v" + ver
        // пинг движка: если gomobile-runtime зависает ещё на старте —
        // увидим это ДО любого запуска фильтра
        thread {
            var pingRes = "ping: ?"
            try {
                val t = thread { pingRes = if (mitm.Mitm.ping() == 42L) "ping: OK" else "ping: ?" }
                t.join(3000)
                if (t.isAlive) pingRes = "ping: ЗАВИС (runtime мёртв)"
            } catch (e: Exception) { pingRes = "ping: " + (e.message ?: "?") }
            prefs.edit().putString("ping", pingRes).apply()
        }
        val chk = findViewById<MaterialCheckBox>(R.id.chkHttps)
        chk.isChecked = prefs.getBoolean("https_mode", false)
        chk.setOnCheckedChangeListener { _, isChecked ->
            prefs.edit().putBoolean("https_mode", isChecked).apply()
            Toast.makeText(this, if (isChecked) "HTTPS-режим: реклама режется внутри трафика. Требуется сертификат (кнопка ниже)." else "Обычный DNS-режим", Toast.LENGTH_LONG).show()
        }
        findViewById<MaterialButton>(R.id.btnCert).setOnClickListener { installCert() }
        val chkNoMitm = findViewById<com.google.android.material.checkbox.MaterialCheckBox>(R.id.chkNoMitm)
        chkNoMitm.isChecked = prefs.getBoolean("no_mitm", false)
        chkNoMitm.setOnCheckedChangeListener { _, isChecked ->
            prefs.edit().putBoolean("no_mitm", isChecked).apply()
            Toast.makeText(this, if (isChecked) "Отладка: 443 напрямую, без MITM" else "MITM включён", Toast.LENGTH_LONG).show()
        }
        findViewById<MaterialButton>(R.id.btnApps).setOnClickListener { pickExcludedApps() }
        val chkEmpty = findViewById<com.google.android.material.checkbox.MaterialCheckBox>(R.id.chkEmpty)
        chkEmpty.isChecked = prefs.getBoolean("empty_vpn", false)
        chkEmpty.setOnCheckedChangeListener { _, isChecked ->
            prefs.edit().putBoolean("empty_vpn", isChecked).apply()
            Toast.makeText(this, if (isChecked) "Пустой туннель: только VPN, без движка (диагностика)" else "Обычный режим", Toast.LENGTH_LONG).show()
        }
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
        }
    }

    // Android 14+ запрещает приложениям показывать окно установки ЦА:
    // сохраняем сертификат в общие Загрузки (доступны системному
    // выборщику файлов) и ведём пользователя в настройки безопасности.
    private fun installCert() {
        try {
            val pem = mitm.Mitm.caCertPem(filesDir.absolutePath)
            val name = "ConfigAdBlock-CA.crt"
            if (Build.VERSION.SDK_INT >= 29) {
                val values = ContentValues().apply {
                    put(MediaStore.Downloads.DISPLAY_NAME, name)
                    put(MediaStore.Downloads.MIME_TYPE, "application/x-x509-ca-cert")
                    put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
                }
                val uri = contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                if (uri == null) { Toast.makeText(this, "Не удалось сохранить сертификат", Toast.LENGTH_LONG).show(); return }
                contentResolver.openOutputStream(uri)?.use { it.write(pem) }
            } else {
                val dir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
                dir.mkdirs()
                File(dir, name).writeBytes(pem)
            }
            Toast.makeText(this, "Сертификат сохранён в Загрузки. Дальше: Настройки -> Безопасность -> Установить сертификат -> CA-сертификат -> выбрать " + name, Toast.LENGTH_LONG).show()
            try { startActivity(Intent(Settings.ACTION_SECURITY_SETTINGS)) } catch (_: Exception) {}
        } catch (e: Exception) {
            Toast.makeText(this, "Ошибка: " + (e.message ?: "?"), Toast.LENGTH_LONG).show()
        }
    }

    // Приложения с закреплением сертификатов (Kimi, банки и т.п.) ломаются
    // через MITM — их можно исключить из VPN: без фильтра, но работают.
    private fun pickExcludedApps() {
        try {
            val pm = packageManager
            val li = Intent(Intent.ACTION_MAIN, null).addCategory(Intent.CATEGORY_LAUNCHER)
            val apps = pm.queryIntentActivities(li, 0)
                .map { it.activityInfo.packageName to it.loadLabel(pm).toString() }
                .distinctBy { it.first }.sortedBy { it.second }
            val names = apps.map { it.second }.toTypedArray()
            val pkgs = apps.map { it.first }
            val excluded = prefs.getStringSet("excluded_apps", emptySet()) ?: emptySet()
            val checked = pkgs.map { it in excluded }.toBooleanArray()
            androidx.appcompat.app.AlertDialog.Builder(this)
                .setTitle("Исключить из фильтра")
                .setMultiChoiceItems(names, checked) { _, which, isChecked -> checked[which] = isChecked }
                .setPositiveButton("Сохранить") { _, _ ->
                    val sel = pkgs.filterIndexed { i, _ -> checked[i] }.toSet()
                    prefs.edit().putStringSet("excluded_apps", sel).apply()
                    Toast.makeText(this, "Исключено: " + sel.size + ". Выключи и включи фильтр", Toast.LENGTH_LONG).show()
                }
                .setNegativeButton("Отмена", null)
                .show()
        } catch (e: Exception) {
            Toast.makeText(this, "Ошибка: " + (e.message ?: "?"), Toast.LENGTH_LONG).show()
        }
    }

    private fun saveStopToLog() {
        try {
            val prefs = getSharedPreferences("stats", MODE_PRIVATE)
            prefs.edit().putString("lasterr", "выключаю...").apply()
        } catch (_: Exception) {}
    }

    private fun logClick(msg: String) {
        try {
            val prefs = getSharedPreferences("stats", MODE_PRIVATE)
            val ts = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US).format(java.util.Date())
            val log = (prefs.getString("log", "") ?: "") + ts + " " + msg + "\n"
            prefs.edit().putString("log", log.takeLast(1500)).apply()
        } catch (_: Exception) {}
    }

    private fun startFilter() {
        val i = Intent(this, FilterService::class.java)
        i.putExtra("https", prefs.getBoolean("https_mode", false))
        try {
            startForegroundService(i)
            logClick("сервис запущен")
        } catch (e: Exception) {
            logClick("СЕРВИС НЕ ЗАПУСТИЛСЯ: " + (e.message ?: "?") + " " + e.javaClass.simpleName)
        }
    }

    override fun onResume() {
        super.onResume()
        updateUi()
        handler.post(ticker)
    }

    override fun onPause() {
        super.onPause()
        handler.removeCallbacks(ticker)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == 42 && resultCode == RESULT_OK) {
            startFilter()
        } else if (requestCode == 42) {
            try { prefs.edit().putString("lasterr", "Разрешение VPN не выдано").apply() } catch (_: Exception) {}
        }
    }

    private fun updateUi() {
        val btn = findViewById<MaterialButton>(R.id.btnToggle)
        val stats = findViewById<TextView>(R.id.tvStats)
        val err = findViewById<TextView>(R.id.tvError)
        val running = FilterService.isRunning
        val consentNeeded = try { VpnService.prepare(this) != null } catch (e: Exception) { false }
        val lasterr = prefs.getString("lasterr", "") ?: ""
        btn.text = when {
            running -> "ВЫКЛЮЧИТЬ"
            consentNeeded -> "РАЗРЕШИТЬ VPN"
            else -> "ВКЛЮЧИТЬ"
        }
        val logText = prefs.getString("log", "") ?: ""
        val sst = prefs.getString("stackstats", "") ?: ""
        val mst = prefs.getString("mitmstats", "") ?: ""
        val lc = (if (mst.isNotEmpty()) mst + "\n" else "") + (if (sst.isNotEmpty()) sst + "\n" else "") + "TCP " + prefs.getLong("tcp_try", 0) + "/" + prefs.getLong("tcp_ok", 0) + " DNS " + prefs.getLong("udp_try", 0) + "/" + prefs.getLong("dns_got", 0) + "/" + prefs.getLong("udp_ok", 0) + "\n443: " + prefs.getLong("t443", 0) + " quic: " + prefs.getLong("quic", 0) + "\nпрокси: ok " + prefs.getLong("gp_ok", 0) + " fail " + prefs.getLong("gp_fail", 0) + " dial " + prefs.getLong("gp_dial", 0)
        val eerr = prefs.getString("eng_err", "") ?: ""
        val st = prefs.getString("selftest", "") ?: ""
        val pst = prefs.getString("proxy_state", "") ?: ""
        val fl = prefs.getString("flowlog", "") ?: ""
        val vpna = prefs.getString("vpn_alive", "") ?: ""
        val ping = prefs.getString("ping", "") ?: ""
        err.text = when {
            running -> {
                val base = if (prefs.getBoolean("https_mode", false)) "HTTPS-фильтрация работает" else "Фильтр работает"
                // ВАЖНО: никаких прямых вызовов mitm.* здесь — только prefs.
                // Прямой gomobile-вызов с главного потока блокирует UI,
                // если движок подвис (кнопки "заедали" именно поэтому).
                if (prefs.getBoolean("https_mode", false)) base + (if (vpna.isNotEmpty()) " (" + vpna + ")" else "") + "\n" + lc + (if (pst.isNotEmpty()) "\n" + pst else "") + (if (st.isNotEmpty()) "\n" + st else "") + (if (fl.isNotEmpty()) "\n" + fl else "") + (if (eerr.isNotEmpty()) "\nERR: " + eerr else "")
                else base
            }
            consentNeeded -> "Нужно разрешение системы — жми кнопку"
            else -> (if (ping.isNotEmpty()) ping + "\n" else "") + "Последнее: " + lasterr + "\n" + lc + (if (pst.isNotEmpty()) "\n" + pst else "") + (if (st.isNotEmpty()) "\n" + st else "") + (if (fl.isNotEmpty()) "\n" + fl else "") + (if (eerr.isNotEmpty()) "\nERR: " + eerr else "") + "\n\nЖурнал:\n" + logText
        }
        err.textSize = if (running || consentNeeded) 13f else 11f
        stats.text = "Всего запросов: " + prefs.getInt("total", 0) + "\nЗаблокировано: " + prefs.getInt("blocked", 0) + "\nПропущено: " + prefs.getInt("allowed", 0)
        btn.setOnClickListener {
            btn.isEnabled = false
            btn.postDelayed({ btn.isEnabled = true }, 800)
            if (FilterService.isRunning) {
                saveStopToLog()
                val si = Intent(this, FilterService::class.java)
                si.action = "STOP"
                startService(si)
                FilterService.isRunning = false
                btn.postDelayed({ updateUi() }, 400)
                btn.postDelayed({ updateUi() }, 1500)
            } else {
                logClick("ВКЛЮЧИТЬ нажато")
                try {
                    val i = VpnService.prepare(this)
                    logClick("consent нужен=" + (i != null))
                    if (i != null) {
                        startActivityForResult(i, 42)
                        logClick("диалог согласия показан")
                    } else {
                        startFilter()
                        btn.postDelayed({ updateUi() }, 500)
                    }
                } catch (e: Exception) {
                    logClick("ОШИБКА клика: " + (e.message ?: "?") + " " + e.javaClass.simpleName)
                }
            }
        }
    }
}
