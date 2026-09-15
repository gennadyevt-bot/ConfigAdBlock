package com.config.adblock

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.button.MaterialButton

class MainActivity : AppCompatActivity() {

    private lateinit var prefs: android.content.SharedPreferences
    private val handler = Handler(Looper.getMainLooper())
    @Volatile private var busy = false
    private val ticker = object : Runnable {
        override fun run() { refreshUi(); handler.postDelayed(this, 1000) }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        prefs = getSharedPreferences("stats", MODE_PRIVATE)
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
        }
    }

    override fun onResume() {
        super.onResume()
        refreshUi()
        handler.post(ticker)
    }

    override fun onPause() {
        super.onPause()
        handler.removeCallbacks(ticker)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        busy = false
        if (requestCode == 42 && resultCode == RESULT_OK) {
            startForegroundService(Intent(this, FilterService::class.java))
        }
    }

    private fun refreshUi() {
        if (busy) return
        val btn = findViewById<MaterialButton>(R.id.btnToggle)
        val stats = findViewById<TextView>(R.id.tvStats)
        val running = FilterService.isRunning
        btn.text = if (running) "ВЫКЛЮЧИТЬ" else "ВКЛЮЧИТЬ"
        stats.text = "Заблокировано: ${prefs.getInt("blocked", 0)}\nПропущено: ${prefs.getInt("allowed", 0)}"
        btn.setOnClickListener { onToggle(btn) }
    }

    private fun onToggle(btn: MaterialButton) {
        if (busy) return
        busy = true
        val wantStart = !FilterService.isRunning
        btn.text = if (wantStart) "ВКЛЮЧЕНИЕ..." else "ВЫКЛЮЧЕНИЕ..."
        btn.isEnabled = false
        if (wantStart) {
            val i = VpnService.prepare(this)
            if (i != null) startActivityForResult(i, 42)
            else startForegroundService(Intent(this, FilterService::class.java))
        } else {
            stopService(Intent(this, FilterService::class.java))
        }
        handler.postDelayed({ busy = false; refreshUi() }, 700)
    }
}
