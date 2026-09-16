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
        httpsMode = intent?.getBooleanExtra("https", false) == true
        val emptyMode = try { getSharedPreferences("stats", MODE_PRIVATE).getBoolean("empty_vpn", false) } catch (_: Exception) { false }
        saveErr("SVC onStartCommand https=" + httpsMode + " empty=" + emptyMode)
        try { saveErr("alwaysOn=" + isAlwaysOn + " lockdown=" + isLockdownEnabled) } catch (_: Exception) {}
        try { getSharedPreferences("stats", MODE_PRIVATE).edit().putString("lasterr", "").apply() } catch (_: Exception) {}
        try { startForeground(1, buildNotification(if (httpsMode) "Фильтр работает (HTTPS)" else "Фильтр работает")) } catch (e: Exception) { saveErr("FGS: " + (e.message ?: "?")) }
        if (!isRunning) {
            running = true
            isRunning = true
            thread { if (emptyMode) runEmptyVpn() else if (httpsMode) runHttpsFilter() else runFilter() }
        }
        return START_NOT_STICKY
    }

    // Остановка: движок гасим в фоновом потоке (engine.Stop() может
    // подвиснуть, а onDestroy идёт по главному), killProcess гарантирует,
    // что ядро закроет detached fd и Android освободит VPN-слот.
    override fun onDestroy() {
        saveErr("SVC onDestroy")
        running = false
        isRunning = false
        thread {
            try { mitm.Mitm.stopTunnel() } catch (_: Exception) {}
            try { mitm.Mitm.stopProxy() } catch (_: Exception) {}
        }
        try { tun?.close() } catch (_: Exception) {}
        super.onDestroy()
        android.os.Process.killProcess(android.os.Process.myPid())
    }

    private fun buildNotification(text: String): Notification {
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        nm.createNotificationChannel(NotificationChannel(CH, "Работа фильтра", NotificationManager.IMPORTANCE_LOW))
        val pi = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        return Notification.Builder(this, CH)
            .setSmallIcon(R.drawable.ic_stat)
            .setContentTitle("Config AdBlock")
            .setContentText(text)
            .setContentIntent(pi)
            .build()
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
        if (findInDownloads(name) != null) return
        if (Build.VERSION.SDK_INT >= 29) {
            val values = ContentValues().apply {
                put(MediaStore.Downloads.DISPLAY_NAME, name)
                put(MediaStore.Downloads.MIME_TYPE, "application/octet-stream")
                put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
            }
            val u = contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values) ?: return
            contentResolver.openOutputStream(u)?.use { it.write(data) }
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
            applyExclusions(b)
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
            val blFile = File(filesDir, "blocklist.txt")
            try {
                assets.open("blocklist.txt").bufferedReader().use { r ->
                    blFile.writeText(r.readText())
                }
            } catch (e: Exception) { saveErr("Списка нет: " + (e.message ?: "?")) }
            try {
                mitm.Mitm.startProxy(filesDir.absolutePath, blFile.absolutePath)
                getSharedPreferences("stats", MODE_PRIVATE).edit().putString("proxy_state", "прокси: OK").apply()
            } catch (e: Exception) {
                saveErr("ПРОКСИ НЕ ЗАПУСТИЛСЯ: " + (e.message ?: "?"))
                getSharedPreferences("stats", MODE_PRIVATE).edit().putString("proxy_state", "ПРОКСИ: " + (e.message ?: "?")).apply()
                return
            }
            // MTU ОБЯЗАН совпадать со стеком (8500): иначе стек шлёт
            // пакеты больше интерфейса и TUN их молча дропает — «интернета нет»
            val b = Builder()
                .setSession("Config AdBlock HTTPS")
                .setMtu(1500)
                .addAddress("10.0.0.2", 32)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("10.0.0.2")
                .addDisallowedApplication(packageName)
            applyExclusions(b)
            saveErr("исключений: " + (getSharedPreferences("stats", MODE_PRIVATE).getStringSet("excluded_apps", emptySet()) ?: emptySet()).size)
            var tries = 0
            while (tries < 3 && pfd == null && running) {
                tries++
                pfd = try { b.establish() } catch (e: Exception) { saveErr("VPN слот: " + (e.message ?: "ошибка")); null }
                if (pfd == null) {
                    saveErr("Слот недоступен. Переспрашиваю разрешение ($tries/3)...")
                    try {
                        val pi = VpnService.prepare(this)
                        if (pi != null) { pi.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK); startActivity(pi) }
                    } catch (e: Exception) { saveErr("Запрос разрешения: " + (e.message ?: "?")) }
                    try { Thread.sleep(2500) } catch (e: Exception) {}
                }
            }
            if (pfd == null) { saveErr("Слот VPN недоступен после 3 попыток"); return }
            try { getSharedPreferences("stats", MODE_PRIVATE).edit().putString("lasterr", "").apply() } catch (_: Exception) {}
            tun = pfd
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
            thread { try { mitm.Mitm.netSelfTest() } catch (_: Exception) {} }
            try { mitm.Mitm.startTunnel(fd.toLong(), 1500) }
            catch (e: Exception) { saveErr("Стек: " + (e.message ?: "?")); return }
            saveErr("туннель поднят, фильтр работает")
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
                    getSharedPreferences("stats", MODE_PRIVATE).edit()
                        .putLong("tcp_try", mitm.Mitm.tcpTry())
                        .putLong("tcp_ok", mitm.Mitm.tcpCount())
                        .putLong("udp_try", mitm.Mitm.udpTry())
                        .putLong("udp_ok", mitm.Mitm.udpCount())
                        .putLong("dns_got", mitm.Mitm.dnsGot())
                        .putString("eng_err", mitm.Mitm.lastErr())
                        .putString("selftest", mitm.Mitm.selfTestResult())
                        .putString("flowlog", mitm.Mitm.flowLog())
                        .apply()
                } catch (e: Exception) { break }
            }
        } catch (e: Exception) {
            saveErr("КРАХ HTTPS: " + (e.message ?: "?") + " " + e.javaClass.simpleName)
        } finally {
            saveErr("стоп HTTPS")
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
