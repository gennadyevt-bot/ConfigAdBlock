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
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.button.MaterialButton
import com.google.android.material.checkbox.MaterialCheckBox
import java.io.File
import java.net.Inet6Address
import java.net.InetAddress
import java.net.NetworkInterface
import kotlin.concurrent.thread

class MainActivity : AppCompatActivity() {
    private var cbAvailLogged = false

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
        prefs.edit().putBoolean("no_mitm", false).apply()
        chkNoMitm.isChecked = false
        chkNoMitm.visibility = android.view.View.GONE
        findViewById<MaterialButton>(R.id.btnApps).setOnClickListener { pickExcludedApps() }
        findViewById<MaterialButton>(R.id.btnResetCa).setOnClickListener { resetCa() }
        val chkBr = findViewById<com.google.android.material.checkbox.MaterialCheckBox>(R.id.chkBrowsers)
        chkBr.isChecked = prefs.getBoolean("browsers_only", true)
        chkBr.setOnCheckedChangeListener { _, isChecked ->
            prefs.edit().putBoolean("browsers_only", isChecked).apply()
            Toast.makeText(this, if (isChecked) "Режим: фильтруем только Chrome/Яндекс, остальное работает как обычно" else "Режим: все приложения через фильтр", Toast.LENGTH_LONG).show()
        }
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
            val fp = CaDiagnostics.fingerprint(CaDiagnostics.certificate(pem))
            val name = "ConfigAdBlock-CA-" + fp.take(16) + ".crt"
            if (Build.VERSION.SDK_INT >= 29) {
                val values = ContentValues().apply {
                    put(MediaStore.Downloads.DISPLAY_NAME, name)
                    put(MediaStore.Downloads.MIME_TYPE, "application/x-x509-ca-cert")
                    put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
                }
                val uri = contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                if (uri == null) { Toast.makeText(this, "Не удалось сохранить сертификат", Toast.LENGTH_LONG).show(); return }
                try {
                    val stream = contentResolver.openOutputStream(uri) ?: error("Не удалось открыть файл сертификата")
                    stream.use { it.write(pem) }
                } catch (e: Exception) {
                    contentResolver.delete(uri, null, null)
                    throw e
                }
            } else {
                val dir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
                dir.mkdirs()
                File(dir, name).writeBytes(pem)
            }
            prefs.edit().putString("ca_export_name", name).apply()
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

    // Сброс CA: удаляет текущую пару сертификатов (в приложении и бэкапах
    // в Загрузках). При следующем включении движок сгенерирует СВЕЖУЮ пару —
    // гарантия совпадения с тем, что пользователь установит в систему.
    // Старый сертификат в системе после этого станет мусором — удали его
    // в настройках (Настройки → Безопасность → Учётные данные пользователя).
    private fun resetCa() {
        if (FilterService.isRunning) {
            Toast.makeText(this, "Сначала выключите фильтр. Сброс меняет CA и требует новой установки.", Toast.LENGTH_LONG).show()
            return
        }
        try {
            filesDir.listFiles()?.forEach { f ->
                if (f.name == "ca.crt" || f.name == "ca.key") f.delete()
            }
            try {
                val dir = getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS)
                File(dir, "ConfigAdBlock-CA.crt").delete()
                File(dir, "ConfigAdBlock-CA.key").delete()
            } catch (_: Exception) {}
            Toast.makeText(this, "Сертификат сброшен. Теперь: 1) удали старый в настройках телефона 2) нажми УСТАНОВИТЬ СЕРТИФИКАТ и поставь новый 3) включи фильтр", Toast.LENGTH_LONG).show()
        } catch (e: Exception) {
            Toast.makeText(this, "Ошибка: " + (e.message ?: "?"), Toast.LENGTH_LONG).show()
        }
    }

    // Диагностика IPv6-bypass (GPT): есть ли на устройстве рабочий IPv6,
    // куда маршрутизирует VPN, и резолвится ли lenta.ru в AAAA.
    private var v6cache = ""
    private var v6cacheAt = 0L
    private var aaaaCache = ""

    private fun ipv6Diag(): String {
        val now = System.currentTimeMillis()
        if (v6cache.isNotEmpty() && now - v6cacheAt < 60_000) return v6cache
        val v6addrs = mutableListOf<String>()
        val v4addrs = mutableListOf<String>()
        try {
            val ifs = NetworkInterface.getNetworkInterfaces()
            while (ifs != null && ifs.hasMoreElements()) {
                val ni = ifs.nextElement()
                if (!ni.isUp || ni.isLoopback) continue
                val addrs = ni.inetAddresses
                while (addrs.hasMoreElements()) {
                    val a = addrs.nextElement()
                    try {
                        if (a is Inet6Address) {
                            val h = a.hostAddress ?: continue
                            if (!h.startsWith("fe80:") && !h.startsWith("::1")) {
                                v6addrs.add(ni.name + "=" + h.split("%")[0])
                            }
                        } else {
                            v4addrs.add(ni.name + "=" + (a.hostAddress ?: "?"))
                        }
                    } catch (_: Exception) {}
                }
            }
        } catch (_: Exception) {}
        // Флаг ipv6_routed выставляет FilterService при построении туннеля
        val routed = prefs.getBoolean("ipv6_routed", false)
        val hasV6 = v6addrs.isNotEmpty()
        val line = "IPv6 BYPASS POSSIBLE: " + (if (hasV6 && !routed) "YES" else "NO") +
            " | v6: " + (if (hasV6) v6addrs.take(3).joinToString(",") else "none") +
            " | v4: " + (if (v4addrs.isNotEmpty()) v4addrs.take(3).joinToString(",") else "none")
        v6cache = line
        v6cacheAt = now
        if (aaaaCache.isEmpty()) {
            Thread {
                try {
                    val all = InetAddress.getAllByName("lenta.ru")
                    val a4 = all.count { it !is Inet6Address }
                    val a6 = all.count { it is Inet6Address }
                    aaaaCache = "lenta.ru: A=" + a4 + " AAAA=" + a6
                } catch (e: Exception) {
                    aaaaCache = "lenta.ru resolve FAIL"
                }
            }.start()
        }
        return line + (if (aaaaCache.isNotEmpty()) "\n" + aaaaCache else "")
    }

    // 2.0.12: префиксы SHA-256 всех CA с тем же именем (диагностика
    // "других CA с тем же именем: 5" - чтобы отличить текущий от старых).
    private fun caTwinsLine(): String {
        return try {
            val tf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            tf.init(null as java.security.KeyStore?)
            val tm = tf.trustManagers[0] as X509TrustManager
            val sb = StringBuilder()
            var n = 0
            for (c in tm.acceptedIssuers) {
                if (c.subjectX500Principal.name.contains("Config AdBlock")) {
                    n++
                    val d = java.security.MessageDigest.getInstance("SHA-256").digest(c.encoded)
                    sb.append(String.format("%02X%02X%02X... ", d[0], d[1], d[2]))
                }
            }
            "SAME-NAME CA count=" + n + " prefixes: " + (if (sb.isEmpty()) "-" else sb.toString()) + "\n"
        } catch (e: Exception) {
            "SAME-NAME CA scan fail: " + (e.message ?: "?") + "\n"
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
        thread {
            val result = CaDiagnostics.inspect(this@MainActivity)
            prefs.edit().putString("ca_diagnostics", result).apply()
        }
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
        // Журнал: пока сервис жив — текущий поток FlowLog; после STOP —
        // сохранённый снапшот последней сессии (GPT: лог не должен
        // исчезать раньше анализа).
        // transport-core-v2: текущий log НИКОГДА не заменяем старым last_log —
        // иначе после неудачного запуска реальная ошибка теряется.
        var logText = "--- CURRENT LOG ---\n" + (prefs.getString("log", "") ?: "")
        val lastLog = prefs.getString("last_log", "") ?: ""
        if (lastLog.isNotEmpty()) {
            logText = logText + "\n\n--- PREVIOUS SESSION ---\n" + lastLog
        }
        // 0.5.73 (GPT): видимый список последних SNI с вердиктами
        val sniLog = prefs.getString("snilog", "") ?: ""
        if (sniLog.isNotEmpty()) {
            logText = logText + "\n--- SNI (последние, сверху новые) ---\n" + sniLog
        }
        // 0.5.79 (GPT): видимый список разрешённых DNS-доменов
        val dnsAllow = prefs.getString("dnsallow", "") ?: ""
        if (dnsAllow.isNotEmpty()) {
            logText = logText + "\n--- DNS_ALLOW (последние, сверху новые) ---\n" + dnsAllow
        }
        // 222: Yandex Content Blocker - статус и кнопка настройки
        val ybInstalled = try { packageManager.getPackageInfo("com.yandex.browser", 0); true } catch (_: Exception) { false }
        val cbServed = prefs.getInt("cb_served", 0)
        val cbRulesReady = (prefs.getString("log", "") ?: "").contains("YANDEX_CB_RULES_READY")
        try {
            val tvCb = findViewById<android.widget.TextView>(R.id.tvYandexCb)
            val btnCb = findViewById<com.google.android.material.button.MaterialButton>(R.id.btnYandexCb)
            if (ybInstalled) {
                tvCb.text = "Яндекс.Браузер: найден. Откройте настройки браузера и включите ConfigAdBlock" +
                    (if (cbServed > 0) " (запросов правил: " + cbServed + ")" else if (cbRulesReady) " (правила готовы)" else "")
                btnCb.visibility = android.view.View.VISIBLE
                btnCb.setOnClickListener {
                    val i = Intent("com.yandex.browser.contentBlocker.ACTION_SETTING")
                    i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    try {
                        startActivity(i)
                        logClick("YANDEX_CB_OPEN_SETTINGS")
                    } catch (_: Exception) {
                        val i2 = Intent("com.samsung.android.sbrowser.contentBlocker.ACTION_SETTING")
                        i2.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                        try {
                            startActivity(i2)
                            logClick("YANDEX_CB_OPEN_SETTINGS samsung-fallback")
                        } catch (_: Exception) {
                            logClick("YANDEX_CB_OPEN_SETTINGS FAIL")
                        }
                    }
                }
                if (!cbAvailLogged) {
                    logClick("YANDEX_CB_AVAILABLE")
                    cbAvailLogged = true
                }
            } else {
                tvCb.text = "Яндекс.Браузер: не установлен (Content Blocker недоступен)"
                btnCb.visibility = android.view.View.GONE
            }
        } catch (_: Exception) {}
        val sst = prefs.getString("stackstats", "") ?: ""
        val mst = prefs.getString("mitmstats", "") ?: ""
        val tst = prefs.getString("tunstats", "") ?: ""
        val cai = prefs.getString("cainfo", "") ?: ""
        val lfv = prefs.getString("leafverify", "") ?: ""
        val modeline = prefs.getString("modeline", "") ?: ""
        val dtx = prefs.getLong("dir_tx", 0)
        val drx = prefs.getLong("dir_rx", 0)
        val v6line = ipv6Diag()
        val sessN = prefs.getLong("sess_n", 0)
        val sessAt = prefs.getLong("sess_at", 0)
        val lastAt = prefs.getLong("last_at", 0)
        val lastMst = prefs.getString("last_mitmstats", "") ?: ""
        val fmt = java.text.SimpleDateFormat("HH:mm:ss")
        val sessLine = "sess #" + sessN + " start " + (if (sessAt > 0) fmt.format(java.util.Date(sessAt)) else "-") +
            " | QUIC udp443 seen " + prefs.getLong("udp_seen", 0) + " dropped " + prefs.getLong("quic_drops", 0) + " TCP443 fb " + prefs.getLong("t443", 0)
        val lastLine = if (lastAt > sessAt && lastMst.isNotEmpty()) {
            "прошлая сессия @" + fmt.format(java.util.Date(lastAt)) + ": " + lastMst + " fb " + prefs.getLong("last_t443", 0) + " quic " + prefs.getLong("last_udp_seen", 0) + "/" + prefs.getLong("last_quic_drops", 0)
        } else ""
        val lc = (if (modeline.isNotEmpty()) modeline + " dir tx=" + dtx + " rx=" + drx + "\n" else "") + sessLine + "\n" + (if (v6line.isNotEmpty()) v6line + "\n" else "") + (if (cai.isNotEmpty()) cai + " " + lfv + "\n" else "") + caTwinsLine() + (if (mst.isNotEmpty()) mst + "\n" else "") + (if (tst.isNotEmpty()) tst + "\n" else "") + (if (sst.isNotEmpty()) sst + "\n" else "") + (if (lastLine.isNotEmpty()) lastLine + "\n" else "") + "TCP " + prefs.getLong("tcp_try", 0) + "/" + prefs.getLong("tcp_ok", 0) + " DNS " + prefs.getLong("udp_try", 0) + "/" + prefs.getLong("dns_got", 0) + "/" + prefs.getLong("udp_ok", 0) + "\n443: " + prefs.getLong("t443", 0) + " quic: " + prefs.getLong("quic", 0) + "\nпрокси: ok " + prefs.getLong("gp_ok", 0) + " fail " + prefs.getLong("gp_fail", 0) + " dial " + prefs.getLong("gp_dial", 0) + "\n\n--- DZEN DOM DIAG ---\n" + (prefs.getString("dzen_dom_diag", "") ?: "(пусто)")
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
        if (modeline == "MODE=HEV_DNS_SNI") {
            // 2.0.8: всегда показываем хвост flowlog — один тест на Дзене
            // видно: прошёл ли TLS MITM (DZEN_TLS_OK), заинжектился ли CSS
            // (DZEN_HTML_FILTERED) или браузер отверг сертификат
            // (DZEN_TLS_REJECT -> DZEN_BYPASS_DIRECT).
            val flowLines = fl.split("\n").filter { it.isNotBlank() }
            val flowTail = flowLines.subList(java.lang.Math.max(0, flowLines.size - 14), flowLines.size).joinToString("\n")
            err.text = (if (running) "Фильтр DNS/SNI включён" else "Фильтр остановлен") +
                "\n" + sst +
                "\n" + prefs.getString("ca_diagnostics", "CA: проверка…") +
                (prefs.getString("ca_export_name", null)?.let { "\nФайл для установки: " + it } ?: "") +
                (if (flowTail.isNotEmpty())
                    "\n--- DZEN flowlog (последние) ---\n" + flowTail
                else
                    "\nflowlog пуст — открой Дзен в браузере и вернись сюда") +
                (if (!running) "\n\nЖурнал:\n" + logText else "")
        }
        err.textSize = if (running || consentNeeded) 13f else 11f
        stats.text = "Всего запросов: " + prefs.getInt("total", 0) + "\nЗаблокировано: " + prefs.getInt("blocked", 0) + "\nПропущено: " + prefs.getInt("allowed", 0)
        if (modeline == "MODE=HEV_DNS_SNI") stats.text = "Тестовая 2.0 • статистика текущего запуска"
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
