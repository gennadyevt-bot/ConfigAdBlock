package com.config.adblock.filter

/**
 * Фасад контент-фильтра (Этап 2 GPT): объединяет слои фильтрации.
 *
 * Слой 1 — DNS (mitm/tun.go, ветка main, стабильный): режет домены
 *          целиком, транспорт DNS_ONLY_ALL_APPS.
 * Слой 2 — контент (этот модуль): косметика/scriptlets для рекламы,
 *          которую DNS удалить не может (first-party, вёрстка).
 *
 * ВАЖНО: никакого глобального HTTPS MITM здесь нет и не планируется.
 * Доставка стилей/скриптов в браузер — отдельное решение следующего
 * шага (кандидаты: локальный HTTP-прокси с явной настройкой в браузере,
 * per-domain опциональный MITM только для выбранных хостов с fail-open,
 * WebView-инжект для встроенного просмотра).
 */
class ContentFilterEngine(private val cosmetic: CosmeticFilterEngine) {

    /** Стили скрытия для хоста (пустая строка = нечего скрывать). */
    fun stylesheetFor(host: String): String = cosmetic.cssFor(host)

    /** Вставить <style> с правилами скрытия в HTML-ответ.
     *  Используется будущим каналом доставки (прокси/MITM). */
    fun injectCss(html: String, host: String): String {
        val css = stylesheetFor(host)
        if (css.isEmpty()) return html
        val style = "<style data-cablock>\n" + css + "</style>"
        val headClose = html.indexOf("</head>", ignoreCase = true)
        if (headClose > 0) {
            return html.substring(0, headClose) + style + "\n" + html.substring(headClose)
        }
        // нет <head> — вставляем в начало
        return style + "\n" + html
    }
}
