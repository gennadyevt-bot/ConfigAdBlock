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

    // 243: машинно-читаемый статус CA. installedExact=true означает только
    // «точно этот CA найден в AndroidCAStore», НЕ «браузер ему доверяет».
    data class CaStatus(
        val fileExists: Boolean,
        val installedExact: Boolean,
        val engineMatchesFile: Boolean,
        val fingerprint: String,
        val olderSameName: Int
    )

    fun status(context: Context): CaStatus {
        val crt = File(context.filesDir, "ca.crt")
        val fileExists = crt.exists()
        val fp = if (fileExists) sha256Hex(crt.readBytes()) else ""
        var installedExact = false
        var older = 0
        try {
            val ks = KeyStore.getInstance("AndroidCAStore").apply { load(null) }
            val aliases = ks.aliases()
            while (aliases.hasMoreElements()) {
                val a = aliases.nextElement()
                if (!a.startsWith("user:")) continue
                val c = ks.getCertificate(a) as? X509Certificate ?: continue
                if (!c.subjectX500Principal.name.contains("Config AdBlock")) continue
                if (sha256Hex(c.encoded) == fp) installedExact = true else older++
            }
        } catch (_: Exception) {}
        val engineFp = try { mitm.Mitm.activeCAFingerprint() } catch (e: Exception) { "" }
        return CaStatus(
            fileExists = fileExists,
            installedExact = installedExact,
            engineMatchesFile = engineFp.isNotEmpty() && engineFp == fp,
            fingerprint = fp,
            olderSameName = older
        )
    }

    private fun sha256Hex(b: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

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
