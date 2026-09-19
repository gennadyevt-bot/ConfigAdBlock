package com.config.adblock.filter

/**
 * Движок косметических правил (CSS / element hiding), AdGuard-style.
 * Парсит правила вида domain##selector, глобальные ##selector и
 * исключения domain#@#selector. Транспорт не знает — чистая логика,
 * чтобы её можно было подключить к любому каналу доставки CSS/JS
 * (локальный прокси, per-domain MITM, WebView-инжект и т.д.).
 */
class CosmeticFilterEngine {

    private val rules = ArrayList<CosmeticRule>()

    /** Загрузить правила из строк (assets-файл). Пустые строки и
     *  комментарии (! и [Adblock...]) пропускаются. */
    fun load(lines: List<String>) {
        for (raw in lines) {
            val line = raw.trim()
            if (line.isEmpty() || line.startsWith("!") || line.startsWith("[")) continue
            val exc = line.contains("#@#")
            val sep = if (exc) "#@#" else "##"
            val i = line.indexOf(sep)
            if (i < 0) continue
            val domPart = line.substring(0, i).trim()
            val selector = line.substring(i + sep.length).trim()
            if (selector.isEmpty()) continue
            val domains = if (domPart.isEmpty()) emptyList()
                          else domPart.split(",").map { it.trim() }.filter { it.isNotEmpty() }
            rules.add(CosmeticRule(domains, selector, exc))
        }
    }

    /** Совпадение домена правила: точный, поддомен, wildcard-префикс. */
    private fun domainMatches(host: String, pattern: String): Boolean {
        val p = pattern.removePrefix("*.")
        return host == p || host.endsWith("." + p)
    }

    /** CSS-таблица скрытия для конкретного хоста. Исключения (#@#)
     *  вычитаются из итогового набора селекторов. */
    fun cssFor(host: String): String {
        val active = LinkedHashSet<String>()
        val excluded = LinkedHashSet<String>()
        for (r in rules) {
            val applies = r.domains.isEmpty() || r.domains.any { domainMatches(host, it) }
            if (!applies) continue
            if (r.exception) excluded.add(r.selector) else active.add(r.selector)
        }
        active.removeAll(excluded)
        if (active.isEmpty()) return ""
        return active.joinToString(", ") + " { display: none !important; }\n"
    }

    fun ruleCount(): Int = rules.size
}
