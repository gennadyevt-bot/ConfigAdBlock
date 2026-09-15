package com.config.adblock

import android.content.Context

object Blocklist {
    private val domains = HashSet<String>()

    fun load(ctx: Context): Blocklist {
        domains.clear()
        ctx.assets.open("blocklist.txt").bufferedReader().useLines { lines ->
            lines.forEach { raw ->
                val d = raw.trim().lowercase()
                if (d.isNotEmpty() && !d.startsWith("#")) domains.add(d)
            }
        }
        return this
    }

    fun matches(domain: String): Boolean {
        var d = domain.trimEnd('.').lowercase()
        while (d.isNotEmpty()) {
            if (domains.contains(d)) return true
            val idx = d.indexOf('.')
            if (idx < 0) break
            d = d.substring(idx + 1)
        }
        return false
    }
}
