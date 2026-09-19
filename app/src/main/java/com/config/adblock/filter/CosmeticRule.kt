package com.config.adblock.filter

/**
 * Одно косметическое правило (AdGuard-style element hiding).
 *
 * Форматы:
 *   domain##selector          — скрыть на домене и его поддоменах
 *   domain1,domain2##selector — несколько доменов
 *   ##selector                — глобально (все сайты)
 *   domain#@#selector         — ИСКЛЮЧЕНИЕ: отменяет скрытие
 */
data class CosmeticRule(
    val domains: List<String>,   // пустой список = глобальное правило
    val selector: String,
    val exception: Boolean
)
