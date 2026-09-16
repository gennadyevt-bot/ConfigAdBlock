package com.config.adblock

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.button.MaterialButton
import com.google.android.material.checkbox.MaterialCheckBox
import java.io.File

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
        val chk = findViewById<MaterialCheckBox>(R.id.chkHttps)
        chk.isChecked = prefs.getBoolean("https_mode", false)
        chk.setOnCheckedChangeListener { _, isChecked ->
            prefs.edit().putBoolean("https_mode", isChecked).apply()
            Toast.makeText(this, if (isChecked) "HTTPS-режим: реклама режется внутри трафика. Требуется сертификат (кнопка ниже)." else "Обычный DNS-режим", Toast.LENGTH_LONG).show()
        }
        findViewById<MaterialButton>(R.id.btnCert).setOnClickListener { installCert() }
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
        }
    }

    private fun installCert() {
        try {
            val pem = mitm.Mitm.caCertPem(filesDir.absolutePath)
            val dir = getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS) ?: filesDir
            val f = File(dir, "ConfigAdBlock-CA.crt")
            f.writeBytes(pem)
            val uri = androidx.core.content.FileProvider.getUriForFile(this, packageName + ".fileprovider", f)
            val view = Intent(Intent.ACTION_VIEW).apply {
                setDataAndType(uri, "application/x-x509-ca-cert")
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            try {
                startActivity(view)
            } catch (e: Exception) {
                startActivity(Intent(Settings.ACTION_SECURITY_SETTINGS))
                Toast.makeText(this, "Открыл настройки безопасности. Найди сертификат: " + f.absolutePath + " — и установи как сертификат ЦА", Toast.LENGTH_LONG).show()
            }
        } catch (e: Exception) {
            Toast.makeText(this, "Ошибка: " + (e.message ?: "?"), Toast.LENGTH_LONG).show()
        }
    }

    private fun startFilter() {
        val i = Intent(this, FilterService::class.java)
        i.putExtra("https", prefs.getBoolean("https_mode", false))
        startForegroundService(i)
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
        err.text = when {
            running -> if (prefs.getBoolean("https_mode", false)) "HTTPS-фильтрация работает" else "Фильтр работает"
            consentNeeded -> "Нужно разрешение системы — жми кнопку"
            else -> "Последнее: " + lasterr + "\n\nЖурнал:\n" + logText
        }
        err.textSize = if (running || consentNeeded) 13f else 11f
        stats.text = "Всего запросов: " + prefs.getInt("total", 0) + "\nЗаблокировано: " + prefs.getInt("blocked", 0) + "\nПропущено: " + prefs.getInt("allowed", 0)
        btn.setOnClickListener {
            btn.isEnabled = false
            btn.postDelayed({ btn.isEnabled = true }, 800)
            if (FilterService.isRunning) {
                stopService(Intent(this, FilterService::class.java))
                btn.postDelayed({ updateUi() }, 300)
            } else {
                val i = VpnService.prepare(this)
                if (i != null) startActivityForResult(i, 42)
                else {
                    startFilter()
                    btn.postDelayed({ updateUi() }, 500)
                }
            }
        }
    }
}
