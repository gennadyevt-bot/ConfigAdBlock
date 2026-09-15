package com.config.adblock

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
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
        private const val UPSTREAM = "1.1.1.1"
    }

    private var tun: ParcelFileDescriptor? = null
    @Volatile private var running = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(1, buildNotification("Фильтр работает"))
        if (!isRunning) {
            running = true
            isRunning = true
            thread { runFilter() }
        }
        return START_STICKY
    }

    override fun onDestroy() {
        running = false
        isRunning = false
        try { tun?.close() } catch (_: Exception) {}
        super.onDestroy()
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

    private class DnsInfo(val id: Int, val domain: String, val payload: ByteArray, val question: ByteArray)

    private fun runFilter() {
        try {
        val blocked = Blocklist.load(this)
        val b = Builder()
            .setSession("Config AdBlock")
            .addAddress("10.0.0.2", 32)
            .addDnsServer(UPSTREAM)
            .addRoute("1.1.1.1", 32)
            .addRoute("8.8.8.8", 32)
            .addRoute("9.9.9.9", 32)
        val localTun: ParcelFileDescriptor = try { b.establish() } catch (e: Exception) { return } ?: return
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
            val pkt = buf.copyOf(n)
            prefs.edit().putInt("total", prefs.getInt("total", 0) + 1).apply()
            val dns = extractDnsQuery(pkt) ?: continue
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
        } finally {
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
