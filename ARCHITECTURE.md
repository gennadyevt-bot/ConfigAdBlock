# ConfigAdBlock — Этап 2: контент-фильтрация (ветка content-filter-engine)

## Слои
1. **DNS filter** — стабильный слой из main (0.5.81): DNS_ONLY_ALL_APPS,
   TUN 10.0.0.2/32, DNS 10.0.0.1, route 10.0.0.1/32, NXDOMAIN для блок-листа.
2. **Content filter engine** — НОВЫЙ модуль `app/.../filter/`:
   - `CosmeticRule` — правило вида `domain##selector` / `#@#` (исключение);
   - `CosmeticFilterEngine` — парсер + сопоставление по хосту + сборка CSS;
   - `ContentFilterEngine` — фасад: stylesheetFor(host), injectCss(html, host).

## Правила
- assets `cosmetic_rules.txt` (AdGuard-style). Первый кейс: dzen.ru,
  селектор `[data-ad-type="direct"]` — нативные рекламные карточки.

## Жёсткие рамки
- main НЕ меняется; релизы main-версий из этой ветки не делаются;
- НИКАКОГО глобального HTTPS MITM;
- transport/VpnService в этой ветке не трогается;
- scriptlet/JS-правила — следующим шагом, после выбора канала доставки.

## Следующий шаг (ещё НЕ делать)
Выбрать безопасный канал доставки CSS/JS в браузер и только тогда
интегрировать ContentFilterEngine.
