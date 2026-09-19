package com.config.adblock

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.ContentValues
import android.content.Intent
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Environment
import android.os.ParcelFileDescriptor
import android.provider.MediaStore
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import kotlin.concurrent.thread

class FilterService : VpnService() {

    companion object {
        @Volatile var isRunning = false
        private const val CH = "adblock"
        // Яндекс DNS: 1.1.1.1 в РФ заблокирован
        private const val UPSTREAM = "77.88.8.8"
    }

    private var tun: ParcelFileDescriptor? = null
    @Volatile private var running = false
    @Volatile private var httpsMode = false
    private var fgTicks = 0

    private fun saveErr(msg: String) {
        try {
            val prefs = getSharedPreferences("stats", MODE_PRIVATE)
            val ts = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US).format(java.util.Date())
            val log = (prefs.getString("log", "") ?: "") + ts + " " + msg + "\n"
            prefs.edit().putString("log", log.takeLast(1500)).putString("lasterr", msg).apply()
        } catch (_: Exception) {}
    }

    override fun onCreate() {
        super.onCreate()
        saveErr("SVC onCreate")
    }

    override fun onRevoke() {
        saveErr("SVC onRevoke!!! (система отозвала VPN)")
        running = false
        isRunning = false
        super.onRevoke()
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        saveErr("SVC onTaskRemoved")
        super.onTaskRemoved(rootIntent)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == "STOP") {
            saveErr("SVC получен STOP")
            running = false
            isRunning = false
            thread {
                try { mitm.Mitm.stopTunnel() } catch (_: Exception) {}
                try { mitm.Mitm.stopProxy() } catch (_: Exception) {}
            }
            try { stopForeground(true) } catch (_: Exception) {}
            stopSelf()
            return START_NOT_STICKY
        }
        httpsMode = intent?.getBooleanExtra("https", false) == true
        val emptyMode = try { getSharedPreferences("stats", MODE_PRIVATE).getBoolean("empty_vpn", false) } catch (_: Exception) { false }
        saveErr("SVC onStartCommand https=" + httpsMode + " empty=" + emptyMode)
        try { saveErr("alwaysOn=" + isAlwaysOn + " lockdown=" + isLockdownEnabled) } catch (_: Exception) {}
        try { getSharedPreferences("stats", MODE_PRIVATE).edit().putString("lasterr", "").apply() } catch (_: Exception) {}
        saveErr("notifPerm=" + notifPermGranted())
        goForeground(if (httpsMode) "Фильтр работает (HTTPS)" else "Фильтр работает")
        if (!isRunning) {
            running = true
            isRunning = true
            thread { if (emptyMode) runEmptyVpn() else if (httpsMode) runHttpsFilter() else runFilter() }
        }
        return START_NOT_STICKY
    }

    // КРИТИЧНО: остановка движка ТОЛЬКО синхронно и ТОЛЬКО здесь.
    // Фоновый поток был источником гонки: он успевал закрыть fd уже
    // НОВОГО туннеля (глобальное состояние Go, один процесс) — система
    // видела мёртвый TUN и сносила VPN (ключик исчезал через секунды).
    // killProcess в конце гарантирует, что ядро закроет detached fd.
    override fun onDestroy() {
        saveErr("SVC onDestroy")
        running = false
        isRunning = false
        try { mitm.Mitm.stopTunnel() } catch (_: Exception) {}
        try { mitm.Mitm.stopProxy() } catch (_: Exception) {}
        try { tun?.close() } catch (_: Exception) {}
        super.onDestroy()
        android.os.Process.killProcess(android.os.Process.myPid())
    }

    private fun buildNotification(text: String): Notification {
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        nm.createNotificationChannel(NotificationChannel(CH, "Работа фильтра", NotificationManager.IMPORTANCE_DEFAULT))
        val pi = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        return Notification.Builder(this, CH)
            .setSmallIcon(R.drawable.ic_stat)
            .setContentTitle("Config AdBlock")
            .setContentText(text)
            .setContentIntent(pi)
            .setOngoing(true)
            .build()
    }

    // КРИТИЧНО для Android 14: foreground-сервис без ПОКАЗАННОГО
    // уведомления система душит через секунды → VPN умирает вместе
    // с сервисом. Стартуем с явным типом specialUse и повторяем
    // startForeground периодически.
    private fun goForeground(text: String) {
        try {
            val n = buildNotification(text)
            if (Build.VERSION.SDK_INT >= 29) {
                startForeground(1, n, android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
            } else {
                startForeground(1, n)
            }
        } catch (e: Exception) {
            saveErr("FGS не стартовал: " + (e.message ?: "?"))
        }
    }

    private fun notifPermGranted(): Boolean {
        return if (Build.VERSION.SDK_INT >= 33) {
            try { checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) == android.content.pm.PackageManager.PERMISSION_GRANTED } catch (e: Exception) { false }
        } else true
    }

    // ==== Персистентность CA между переустановками ====
    // CA бэкапится в общие Загрузки (они не удаляются при сносе приложения)
    // и восстанавливается в filesDir при первом запуске. Сертификат в
    // системе продолжает подходить после любой переустановки.

    private fun findInDownloads(name: String): Uri? {
        if (Build.VERSION.SDK_INT < 29) return null
        val proj = arrayOf(MediaStore.Downloads._ID, MediaStore.Downloads.DISPLAY_NAME)
        contentResolver.query(MediaStore.Downloads.EXTERNAL_CONTENT_URI, proj,
            MediaStore.Downloads.DISPLAY_NAME + "=?", arrayOf(name), null)?.use { c ->
            if (c.moveToFirst()) return Uri.withAppendedPath(MediaStore.Downloads.EXTERNAL_CONTENT_URI, c.getLong(0).toString())
        }
        return null
    }

    private fun readFromDownloads(name: String): ByteArray? {
        val u = findInDownloads(name) ?: return null
        return contentResolver.openInputStream(u)?.use { it.readBytes() }
    }

    private fun saveToDownloads(name: String, data: ByteArray) {
        if (Build.VERSION.SDK_INT >= 29) {
            try {
                val values = ContentValues().apply {
                    put(MediaStore.Downloads.DISPLAY_NAME, name)
                    put(MediaStore.Downloads.MIME_TYPE, "application/octet-stream")
                    put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
                }
                contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                    ?.let { u -> contentResolver.openOutputStream(u)?.use { it.write(data) } }
            } catch (e: Exception) {
                // конфликт имени (Failed to build unique file) — удалим
                // нашу старую запись с таким именем и повторим один раз
                try {
                    val u = findInDownloads(name)
                    if (u != null) contentResolver.delete(u, null, null)
                    val values = ContentValues().apply {
                        put(MediaStore.Downloads.DISPLAY_NAME, name)
                        put(MediaStore.Downloads.MIME_TYPE, "application/octet-stream")
                        put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
                    }
                    contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                        ?.let { u2 -> contentResolver.openOutputStream(u2)?.use { it.write(data) } }
                } catch (_: Exception) {}
            }
        } else {
            val dir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
            dir.mkdirs()
            File(dir, name).writeBytes(data)
        }
    }

    private fun ensureCaPersist() {
        try {
            val crt = File(filesDir, "ca.crt")
            val key = File(filesDir, "ca.key")
            if (crt.exists() && key.exists()) {
                saveToDownloads("ConfigAdBlock-CA.crt", crt.readBytes())
                saveToDownloads("ConfigAdBlock-CA.key", key.readBytes())
                return
            }
            val dc = readFromDownloads("ConfigAdBlock-CA.crt")
            val dk = readFromDownloads("ConfigAdBlock-CA.key")
            if (dc != null && dk != null) {
                crt.writeBytes(dc)
                key.writeBytes(dk)
                saveErr("CA восстановлен из Загрузок")
            }
        } catch (e: Exception) { saveErr("CA persist: " + (e.message ?: "?")) }
    }

    // ПУСТОЙ ТУННЕЛЬ (диагностика GPT): только establish() и держим fd
    // открытым. Никакого Go. Если системный VPN-ключ исчезает и тут —
    // проблема в Android/service lifecycle, а не в движке.
    private fun runEmptyVpn() {
        saveErr("ПУСТОЙ: старт")
        try {
            val b = Builder()
                .setSession("Config AdBlock EMPTY")
                .setMtu(1500)
                .addAddress("10.0.0.2", 32)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("10.0.0.2")
            val p = b.establish()
            if (p == null) { saveErr("ПУСТОЙ: establish вернул null"); return }
            tun = p
            saveErr("ПУСТОЙ: туннель установлен, держим открытым")
            while (running) {
                try { Thread.sleep(1000) } catch (e: Exception) { break }
            }
        } catch (e: Exception) {
            saveErr("ПУСТОЙ КРАХ: " + (e.message ?: "?") + " " + e.javaClass.simpleName)
        } finally {
            saveErr("ПУСТОЙ: стоп")
            running = false
            isRunning = false
            try { stopForeground(true) } catch (_: Exception) {}
        }
    }

    // Режим HTTPS: full-tunnel -> Go-движок (MITM-прокси 127.0.0.1:8080)
    // с блокировкой доменов из blocklist.txt и косметикой в HTML.
    private fun runHttpsFilter() {
        saveErr("старт HTTPS")
        var pfd: ParcelFileDescriptor? = null
        try {
            ensureCaPersist()
            saveErr("1/5 CA готов")
            val blFile = File(filesDir, "blocklist.txt")
            try {
                assets.open("blocklist.txt").bufferedReader().use { r ->
                    blFile.writeText(r.readText())
                }
            } catch (e: Exception) { saveErr("Списка нет: " + (e.message ?: "?")) }
            saveErr("2/5 вызов startProxy...")
            val pxt = thread {
                try {
                    mitm.Mitm.startProxy(filesDir.absolutePath, blFile.absolutePath)
                    getSharedPreferences("stats", MODE_PRIVATE).edit().putString("proxy_state", "прокси: OK").apply()
                    saveErr("2/5 прокси запущен")
                } catch (e: Exception) {
                    saveErr("ПРОКСИ НЕ ЗАПУСТИЛСЯ: " + (e.message ?: "?"))
                    getSharedPreferences("stats", MODE_PRIVATE).edit().putString("proxy_state", "ПРОКСИ: " + (e.message ?: "?")).apply()
                }
            }
            pxt.join(12000)
            if (pxt.isAlive) {
                saveErr("2/5 startProxy ЗАВИС >12с (Go-движок мёртв)")
                getSharedPreferences("stats", MODE_PRIVATE).edit().putString("proxy_state", "прокси: ЗАВИС").apply()
            }
            try {
                val stg = File(filesDir, "stage.txt")
                if (stg.exists()) saveErr("stage: " + stg.readText())
            } catch (_: Exception) {}
            // MTU ОБЯЗАН совпадать со стеком (8500): иначе стек шлёт
            // пакеты больше интерфейса и TUN их молча дропает — «интернета нет»
            val b = Builder()
                .setSession("Config AdBlock HTTPS")
                .setMtu(1500)
                .addAddress("10.0.0.2", 32)
                .addRoute("0.0.0.0", 0)
                // IPv6 НЕ перехватываем (GPT 0.5.43): тупой ::/0 в v4-only
                // стек превратил бы v6 в blackhole и убил бы интернет.
                // Сначала диагностика (IPv6 BYPASS POSSIBLE на экране),
                // корректное решение — отдельным обоснованным коммитом.
                // addDnsServer сознательно НЕ в цепочке: в режиме «только
                // браузеры» VPN-DNS отравил бы резолвер ВСЕХ приложений
                // (не-allowed физически не достигают 10.0.0.2). Ставим его
                // только в ветке «все приложения» ниже.
            // режим «только браузеры»: VPN захватывает лишь Chrome/Яндекс —
            // остальные приложения гарантированно работают вне туннеля
            // БАГ-ФИКС (GPT): дефолт в сервисе был false, а в чекбоксе true —
            // пока галочку не трогаешь, pref не существует и режим молча
            // оставался «все приложения». Теперь дефолт везде true.
            val browsersOnly = try { getSharedPreferences("stats", MODE_PRIVATE).getBoolean("browsers_only", true) } catch (_: Exception) { true }
            if (browsersOnly) {
                var cnt = 0
                for (pkg in listOf("com.android.chrome", "com.yandex.browser")) {
                    try {
                        b.addAllowedApplication(pkg)
                        val uid = try { packageManager.getApplicationInfo(pkg, 0).uid } catch (_: Exception) { -1 }
                        saveErr("allowed OK: " + pkg + " uid=" + uid)
                        cnt++
                    } catch (e: Exception) {
                        // ПРИЧИНА обязана быть видна — иначе диагностика слепая
                        saveErr("allowed FAIL: " + pkg + " " + e.javaClass.simpleName + ": " + (e.message ?: "?"))
                    }
                }
                if (cnt == 0) {
                    // по требованию GPT: молчаливый фолбэк на VPN всех
                    // приложений ЗАПРЕЩЁН — лучше не поднимать туннель
                    saveErr("allowed пуст — establish ОТМЕНЁН (безопасность)")
                    return
                }
                saveErr("режим: ТОЛЬКО БРАУЗЕРЫ ($cnt)")
                saveErr("disallowed calls=0")
                val noMitmDbg0 = try { getSharedPreferences("stats", MODE_PRIVATE).getBoolean("no_mitm", false) } catch (_: Exception) { false }
                getSharedPreferences("stats", MODE_PRIVATE).edit().putString("modeline",
                    "MODE=BROWSER_ONLY+" + (if (noMitmDbg0) "DIRECT" else "MITM")).apply()
            } else {
                // КЛЮЧЕВОЕ РЕШЕНИЕ: addDnsServer НЕ ставим вообще. Chrome
                // падал с DNS_PROBE_FINISHED_BAD_CONFIG, т.к. VPN-DNS
                // доставался ему лишь частично (1 запрос из сессии).
                // Системный DNS оператора работает исправно, а блокировка
                // рекламы идёт на уровне расшифрованных HTTP-запросов —
                // перехват DNS для MITM-режима не нужен.
                saveErr("VPN-DNS: выкл (системный DNS оператора)")
                // само-исключение ТОЛЬКО здесь, в ветке «все приложения»
                try { b.addDisallowedApplication(packageName) } catch (_: Exception) {}
                applyExclusions(b)
                val noMitmDbg1 = try { getSharedPreferences("stats", MODE_PRIVATE).getBoolean("no_mitm", false) } catch (_: Exception) { false }
                getSharedPreferences("stats", MODE_PRIVATE).edit().putString("modeline",
                    "MODE=ALL+" + (if (noMitmDbg1) "DIRECT" else "MITM")).apply()
                saveErr("режим: все приложения, исключений: " + (getSharedPreferences("stats", MODE_PRIVATE).getStringSet("excluded_apps", emptySet()) ?: emptySet()).size)
            }
            var tries = 0
            while (tries < 5 && pfd == null && running) {
                tries++
                pfd = try { b.establish() } catch (e: Exception) { saveErr("VPN слот: " + (e.message ?: "ошибка")); null }
                if (pfd == null) {
                    saveErr("Слот недоступен ($tries/5), подожду 4с...")
                    try {
                        val pi = VpnService.prepare(this)
                        if (pi != null) { pi.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK); startActivity(pi) }
                    } catch (e: Exception) { saveErr("Запрос разрешения: " + (e.message ?: "?")) }
                    try { Thread.sleep(4000) } catch (e: Exception) {}
                }
            }
            if (pfd == null) {
                if (!running) { saveErr("стоп до поднятия туннеля (это не ошибка)"); return }
                saveErr("Слот VPN недоступен после 5 попыток"); return
            }
            try { getSharedPreferences("stats", MODE_PRIVATE).edit().putString("lasterr", "").apply() } catch (_: Exception) {}
            tun = pfd
            try {
                val myUid = applicationInfo.uid
                saveErr("our uid=" + myUid)
                try {
                    val browsers = listOf(
                        "com.android.chrome", "com.yandex.browser", "org.mozilla.firefox",
                        "com.opera.browser", "com.microsoft.emmx", "com.brave.browser",
                        "com.vivaldi.browser", "mark.via", "com.UCMobile.intl",
                        "com.huawei.browser", "com.sec.android.app.sbrowser"
                    )
                    val found = StringBuilder()
                    for (pkg in browsers) {
                        try {
                            packageManager.getApplicationInfo(pkg, 0)
                            found.append(pkg).append(" ")
                        } catch (_: Exception) {}
                    }
                    saveErr("браузеры: " + (if (found.isEmpty()) "из списка нет" else found.toString()))
                    // дефолтный обработчик https
                    try {
                        val hi = Intent(Intent.ACTION_VIEW, android.net.Uri.parse("https://example.com"))
                        val acts = packageManager.queryIntentActivities(hi, 0)
                        val top = acts.firstOrNull()?.activityInfo?.packageName ?: "?"
                        saveErr("дефолт браузер: " + top)
                    } catch (e: Exception) { saveErr("дефолт: ?") }
                } catch (e: Exception) { saveErr("браузеры: ошибка") }
            } catch (_: Exception) {}
            // явная защита сокетов движка (VPN bypass) + отладочный режим
            try {
                mitm.Mitm.setProtector(object : mitm.Protector {
                    override fun protect(fd: Long): Boolean {
                        return try { this@FilterService.protect(fd.toInt()) } catch (e: Exception) { false }
                    }
                })
            } catch (e: Exception) { saveErr("protect: " + (e.message ?: "?")) }
            try { mitm.Mitm.setDirect443(getSharedPreferences("stats", MODE_PRIVATE).getBoolean("no_mitm", false)) } catch (e: Exception) {}
            val fd = pfd.detachFd()
            saveErr("3/5 вызов startTunnel...")
            val stt = thread {
                try { mitm.Mitm.startTunnel(fd.toLong(), 1500) }
                catch (e: Exception) { saveErr("СТЕК: " + (e.message ?: "?")) }
            }
            stt.join(12000)
            if (stt.isAlive) {
                saveErr("3/5 startTunnel ЗАВИС >12с (Go-движок мёртв)")
                return
            }
            thread { try { mitm.Mitm.netSelfTest() } catch (_: Exception) {} }
            saveErr("4/5 туннель поднят, фильтр работает")
            // SESSION ID (GPT): чтобы нули новой сессии не путать с
            // реальным отсутствием трафика в прошлой.
            val sp0 = getSharedPreferences("stats", MODE_PRIVATE)
            sp0.edit().putLong("sess_n", sp0.getLong("sess_n", 0) + 1)
                .putLong("sess_at", System.currentTimeMillis()).apply()
            while (running) {
                try {
                    Thread.sleep(2000)
                    // система могла сорвать VPN-сессию (always-on другого
                    // приложения, смена сети) — замечаем и честно стопаемся
                    try {
                        val pi = VpnService.prepare(this)
                        if (pi != null) {
                            saveErr("VPN-СЕССИЯ ПОТЕРЯНА СИСТЕМОЙ (слот отдали другому приложению?)")
                            getSharedPreferences("stats", MODE_PRIVATE).edit().putString("vpn_alive", "потерян").apply()
                            break
                        }
                        getSharedPreferences("stats", MODE_PRIVATE).edit().putString("vpn_alive", "жив").apply()
                    } catch (_: Exception) {}
                    fgTicks++
                    if (fgTicks % 15 == 0) goForeground(if (httpsMode) "Фильтр работает (HTTPS)" else "Фильтр работает")
                    getSharedPreferences("stats", MODE_PRIVATE).edit()
                        .putLong("tcp_try", mitm.Mitm.tcpTry())
                        .putLong("tcp_ok", mitm.Mitm.tcpCount())
                        .putLong("udp_try", mitm.Mitm.udpTry())
                        .putLong("udp_ok", mitm.Mitm.udpCount())
                        .putLong("dns_got", mitm.Mitm.dnsGot())
                        .putString("eng_err", mitm.Mitm.lastErr())
                        .putString("selftest", mitm.Mitm.selfTestResult())
                        .putString("flowlog", mitm.Mitm.flowLog())
                        .putString("stackstats", mitm.Mitm.stackStats())
                        .putLong("gp_ok", mitm.Mitm.gpOkExt())
                        .putLong("gp_fail", mitm.Mitm.gpFailExt())
                        .putLong("gp_dial", mitm.Mitm.gpDialExt())
                        .putLong("t443", mitm.Mitm.t443Seen())
                        .putLong("quic", mitm.Mitm.quicRelays())
                        .putLong("udp_seen", mitm.Mitm.udpSeen())
                        .putLong("quic_drops", mitm.Mitm.quicDrops())
                        .putString("mitmstats", mitm.Mitm.mitmStats())
                        .putString("cainfo", mitm.Mitm.caInfo())
                        .putString("leafverify", mitm.Mitm.leafVerify())
                        .putLong("dir_tx", mitm.Mitm.dirTx())
                        .putLong("dir_rx", mitm.Mitm.dirRx())
                        .apply()
                } catch (e: Exception) { break }
            }
        } catch (e: Exception) {
            saveErr("КРАХ HTTPS: " + (e.message ?: "?") + " " + e.javaClass.simpleName)
        } finally {
            saveErr("стоп HTTPS")
            // Снапшот последней сессии (GPT): нули свежего старта не должны
            // затирать цифры, которые пользователь ещё не успел посмотреть.
            try {
                getSharedPreferences("stats", MODE_PRIVATE).edit()
                    .putString("last_mitmstats", mitm.Mitm.mitmStats())
                    .putLong("last_t443", mitm.Mitm.t443Seen())
                    .putLong("last_udp_seen", mitm.Mitm.udpSeen())
                    .putLong("last_quic_drops", mitm.Mitm.quicDrops())
                    .putLong("last_at", System.currentTimeMillis())
                    .putString("last_flowlog", mitm.Mitm.flowLog())
                    .apply()
            } catch (_: Exception) {}
            running = false
            isRunning = false
            try { mitm.Mitm.stopTunnel() } catch (_: Exception) {}
            try { mitm.Mitm.stopProxy() } catch (_: Exception) {}
            try { stopForeground(true) } catch (_: Exception) {}
        }
    }

    // Исключённые пользователем приложения (pinning) обходят VPN целиком
    private fun applyExclusions(b: Builder) {
        try {
            val ex = getSharedPreferences("stats", MODE_PRIVATE).getStringSet("excluded_apps", emptySet()) ?: emptySet()
            for (p in ex) {
                try { b.addDisallowedApplication(p) } catch (_: Exception) {}
            }
        } catch (_: Exception) {}
    }

    private class DnsInfo(val id: Int, val domain: String, val payload: ByteArray, val question: ByteArray)

    private fun runFilter() {
        saveErr("старт")
        try {
            val blocked = try {
                Blocklist.load(this)
            } catch (e: Exception) {
                saveErr("Ошибка списка: " + (e.message ?: "неизвестно"))
                Blocklist.load(this)
            }
            val b = Builder()
                .setSession("Config AdBlock")
                .addAddress("10.0.0.2", 32)
                .addDnsServer(UPSTREAM)
                .addRoute("1.1.1.1", 32)
                .addRoute("8.8.8.8", 32)
                .addRoute("9.9.9.9", 32)
            applyExclusions(b)
            var localTun: ParcelFileDescriptor? = null
            var tries = 0
            while (tries < 3 && localTun == null && running) {
                tries++
                localTun = try { b.establish() } catch (e: Exception) { saveErr("VPN слот: " + (e.message ?: "ошибка")); null }
                if (localTun == null) {
                    saveErr("Слот недоступен. Переспрашиваю разрешение ($tries/3)...")
                    try {
                        val pi = VpnService.prepare(this)
                        if (pi != null) { pi.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK); startActivity(pi) }
                    } catch (e: Exception) { saveErr("Запрос разрешения: " + (e.message ?: "?")) }
                    try { Thread.sleep(2500) } catch (e: Exception) {}
                }
            }
            if (localTun == null) { saveErr("Слот VPN недоступен после 3 попыток"); return }
            try { getSharedPreferences("stats", MODE_PRIVATE).edit().putString("lasterr", "").apply() } catch (_: Exception) {}
            tun = localTun
            val input = FileInputStream(localTun.fileDescriptor)
            val output = FileOutputStream(localTun.fileDescriptor)
            val upstream = DatagramSocket()
            protect(upstream)
            upstream.soTimeout = 8000
            val buf = ByteArray(4096)
            val prefs = getSharedPreferences("stats", MODE_PRIVATE)
            while (running) {
                val n = try { input.read(buf) } catch (e: Exception) { break }
                if (n <= 0) continue
                prefs.edit().putInt("total", prefs.getInt("total", 0) + 1).apply()
                val pkt = buf.copyOf(n)
                val dns = try { extractDnsQuery(pkt) } catch (e: Exception) { null } ?: continue
                if (blocked.matches(dns.domain)) {
                    output.write(wrapUdp(pkt, buildDnsResponse(dns.id, dns.question)))
                    prefs.edit().putInt("blocked", prefs.getInt("blocked", 0) + 1).apply()
                } else {
                    try {
                        upstream.send(DatagramPacket(dns.payload, dns.payload.size, InetAddress.getByName(UPSTREAM), 53))
                        val rp = DatagramPacket(ByteArray(4096), 4096)
                        upstream.receive(rp)
                        output.write(wrapUdp(pkt, rp.data.copyOf(rp.length)))
                        prefs.edit().putInt("allowed", prefs.getInt("allowed", 0) + 1).apply()
                    } catch (e: Exception) { }
                }
            }
        } catch (e: Exception) {
            saveErr("КРАХ: " + (e.message ?: "?") + " " + e.javaClass.simpleName)
        } finally {
            saveErr("стоп")
            running = false
            isRunning = false
            try { tun?.close() } catch (_: Exception) {}
            try { stopForeground(true) } catch (_: Exception) {}
        }
    }

    private fun extractDnsQuery(pkt: ByteArray): DnsInfo? {
        if (pkt.size < 28) return null
        if (pkt[0].toInt() shr 4 != 4) return null
        if ((pkt[9].toInt() and 0xFF) != 17) return null
        val dstPort = ((pkt[22].toInt() and 0xFF) shl 8) or (pkt[23].toInt() and 0xFF)
        if (dstPort != 53) return null
        val udpLen = ((pkt[24].toInt() and 0xFF) shl 8) or (pkt[25].toInt() and 0xFF)
        val dnsOff = 28
        if (pkt.size < dnsOff + 12 || udpLen < 20) return null
        val id = ((pkt[dnsOff].toInt() and 0xFF) shl 8) or (pkt[dnsOff + 1].toInt() and 0xFF)
        var off = dnsOff + 12
        val sb = StringBuilder()
        while (off < pkt.size) {
            val len = pkt[off].toInt() and 0xFF
            if (len == 0) { off++; break }
            if (len > 63) return null
            if (sb.isNotEmpty()) sb.append('.')
            for (i in 1..len) {
                if (off + i >= pkt.size) return null
                sb.append((pkt[off + i].toInt() and 0xFF).toChar())
            }
            off += len + 1
        }
        if (off + 4 > pkt.size) return null
        val qend = off + 4
        val payloadEnd = minOf(dnsOff + udpLen - 8, pkt.size)
        val payload = pkt.copyOfRange(dnsOff, payloadEnd)
        val question = pkt.copyOfRange(dnsOff + 12, qend)
        return DnsInfo(id, sb.toString().lowercase(), payload, question)
    }

    private fun buildDnsResponse(id: Int, question: ByteArray): ByteArray {
        val header = byteArrayOf(
            (id shr 8).toByte(), id.toByte(),
            0x81.toByte(), 0x80.toByte(),
            0, 1, 0, 1, 0, 0, 0, 0
        )
        val answer = byteArrayOf(
            0xC0.toByte(), 0x0C, 0, 1, 0, 1,
            0, 0, 0, 60, 0, 4, 0, 0, 0, 0
        )
        return header + question + answer
    }

    private fun wrapUdp(requestIp: ByteArray, dnsPayload: ByteArray): ByteArray {
        val total = 20 + 8 + dnsPayload.size
        val out = ByteArray(total)
        out[0] = 0x45
        out[2] = (total shr 8).toByte(); out[3] = total.toByte()
        out[4] = 0; out[5] = 1
        out[8] = 64; out[9] = 17
        for (i in 0..3) { out[12 + i] = requestIp[16 + i]; out[16 + i] = requestIp[12 + i] }
        out[10] = 0; out[11] = 0
        val cks = ipChecksum(out, 0, 20)
        out[10] = (cks shr 8).toByte(); out[11] = cks.toByte()
        for (i in 0..1) { out[20 + i] = requestIp[22 + i]; out[22 + i] = requestIp[20 + i] }
        val udpLen = 8 + dnsPayload.size
        out[24] = (udpLen shr 8).toByte(); out[25] = udpLen.toByte()
        out[26] = 0; out[27] = 0
        dnsPayload.copyInto(out, 28)
        return out
    }

    private fun ipChecksum(data: ByteArray, off: Int, len: Int): Int {
        var sum = 0
        var i = off
        while (i < off + len) {
            val hi = data[i].toInt() and 0xFF
            val lo = if (i + 1 < off + len) data[i + 1].toInt() and 0xFF else 0
            sum += (hi shl 8) or lo
            i += 2
        }
        while (sum shr 16 != 0) sum = (sum and 0xFFFF) + (sum shr 16)
        return sum.inv() and 0xFFFF
    }
}
