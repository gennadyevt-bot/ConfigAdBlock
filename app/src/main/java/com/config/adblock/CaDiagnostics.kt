package com.config.adblock

import android.content.Context
import java.io.File
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/** Presence in AndroidCAStore is not proof that another browser trusts this CA. */
object CaDiagnostics {
    fun certificate(pem: ByteArray): X509Certificate =
        CertificateFactory.getInstance("X.509").generateCertificate(pem.inputStream()) as X509Certificate

    fun fingerprint(cert: X509Certificate): String =
        MessageDigest.getInstance("SHA-256").digest(cert.encoded)
            .joinToString("") { "%02X".format(it.toInt() and 255) }

    fun inspect(context: Context): String {
        return try {
            val file = File(context.filesDir, "ca.crt")
            if (!file.isFile) return "CA: файл ещё не создан. Нажмите «Установить сертификат»."
            val current = certificate(file.readBytes())
            val fp = fingerprint(current)
            val store = KeyStore.getInstance("AndroidCAStore").apply { load(null) }
            var exact = false
            var older = 0
            val aliases = store.aliases()
            while (aliases.hasMoreElements()) {
                val cert = store.getCertificate(aliases.nextElement()) as? X509Certificate ?: continue
                if (cert.encoded.contentEquals(current.encoded)) exact = true
                else if (cert.subjectX500Principal == current.subjectX500Principal) older++
            }
            val active = mitm.Mitm.activeCAFingerprint()
            val signing = when {
                active.isEmpty() -> "CA движка: ещё не загружен"
                active.equals(fp, ignoreCase = true) -> "CA движка совпадает с файлом"
                else -> "CA движка НЕ совпадает: выключите и включите фильтр"
            }
            val presence = if (exact) "Этот CA найден в хранилище Android. Доверие браузера проверяется отдельно."
                else "Этот CA не найден в доступном хранилище Android. Нажмите «Установить сертификат»."
            val validity = try { current.checkValidity(); "Срок CA действителен" } catch (_: Exception) { "Срок CA недействителен" }
            "CA SHA-256: $fp\n$signing\n$presence\n$validity" +
                (if (older > 0) "\nДругих CA с тем же именем: $older" else "")
        } catch (e: Exception) {
            "CA: проверка недоступна — ${e.message ?: e.javaClass.simpleName}"
        }
    }
}
