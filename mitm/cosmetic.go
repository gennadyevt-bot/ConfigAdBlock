package mitm

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// Стили + скрипт, вырезающие баннерные блоки, которые подгрузились с
// "своих" доменов новостных сайтов (lenta/rambler/gazeta подают часть
// рекламы с основных доменов — режем по селекторам).
var cosmeticInject = []byte(`<style>
[id*="adfox"],[class*="adfox"],[id*="AdFox"],[class*="AdFox"],
[id*="yandex_direct"],[class*="yandex_direct"],[class*="yandex-direct"],[class*="YaDirect"],
[class*="adsbygoogle"],[id*="google_ads"],[class*="banner"],[id*="banner"],[class*="Banner"],[id*="Banner"],
[class*="ads_"],[id*="ads_"],[class*="-ads"],[class*=" ad-"],[id*=" ad-"],
[data-marker="advert"],[data-testid*="advert"],[data-testid*="ad-"],
[class*="promo-block"],[class*="Promo"],[id*="promo"],
[class*="rnet"],[class*="r-ads"],[class*="r-banner"],[id*="r-banner"],
[aria-label*="реклам"],[class*="ad-slot"],[id*="ad-slot"],[class*="adunit"],[id*="adunit"],
[class*="commercial"],[id*="commercial"],[class*="sponsor"],[id*="sponsor"],
	/* Дзен: нативные рекламные карточки */
	[data-ad-type="direct"],
	[data-ad-type="banner"],
	div[aria-label="Лента Дзена"] article:has(> div[data-ad-type="direct"]),
	div[id^="ad-"][class*="__isStretched"],
	div[class*="MyTargetAdvert"],
	div[data-testid="bottom-ad"],
	div[class*="__advertItem "]
{display:none!important;visibility:hidden!important;height:0!important;min-height:0!important;max-height:0!important;overflow:hidden!important}
</style><script>(function(){function k(){document.querySelectorAll('[id*="adfox"],[class*="adfox"],[class*="yandex_direct"],[class*="yandex-direct"],[class*="adsbygoogle"],[class*="banner"],[id*="banner"],[class*="-ads"],[class*=" ad-"],[data-marker="advert"],[class*="promo-block"],[class*="commercial"],[class*="rnet"],[class*="r-ads"],[aria-label*="реклам"],[data-ad-type="direct"],[data-ad-type="banner"],div[id^="ad-"][class*="__isStretched"],div[class*="MyTargetAdvert"],div[data-testid="bottom-ad"],div[class*="__advertItem "]').forEach(function(e){e.style.display="none";e.style.height="0";e.style.overflow="hidden"})}k();new MutationObserver(k).observe(document.documentElement,{childList:true,subtree:true})})();</script>`)

// filterHTML: text/html -> вставляем косметику после <head>.
// Сжатие (gzip) прозрачно распаковывается и упаковывается обратно.
func filterHTML(resp *http.Response) *http.Response {
	if resp == nil || resp.Request == nil || resp.Body == nil {
		return resp
	}
	if resp.StatusCode != http.StatusOK {
		return resp
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		return resp
	}
	enc := strings.ToLower(resp.Header.Get("Content-Encoding"))
	raw, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || len(raw) < 256 {
		resp.Body = io.NopCloser(bytes.NewReader(raw))
		return resp
	}
	// 2.0.3: Content-Encoding непустой и не gzip (br/deflate) -
	// НЕ модифицируем body, отдаём как есть
	if enc != "" && enc != "gzip" {
		resp.Body = io.NopCloser(bytes.NewReader(raw))
		return resp
	}
	if enc == "gzip" {
		zr, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			resp.Body = io.NopCloser(bytes.NewReader(raw))
			return resp
		}
		raw, err = io.ReadAll(zr)
		zr.Close()
		if err != nil {
			resp.Body = io.NopCloser(bytes.NewReader(nil))
			return resp
		}
	}
	mod := injectAfterHead(raw)
	if enc == "gzip" {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_, _ = zw.Write(mod)
		_ = zw.Close()
		mod = buf.Bytes()
	} else {
		resp.Header.Del("Content-Length")
	}
	resp.Body = io.NopCloser(bytes.NewReader(mod))
	resp.ContentLength = int64(len(mod))
	resp.Header.Set("Content-Length", strconv.Itoa(len(mod)))
	return resp
}

func injectAfterHead(body []byte) []byte {
	lower := bytes.ToLower(body)
	idx := bytes.Index(lower, []byte("<head"))
	if idx < 0 {
		idx = bytes.Index(lower, []byte("<html"))
	}
	if idx >= 0 {
		if gt := bytes.IndexByte(body[idx:], '>'); gt >= 0 {
			pos := idx + gt + 1
			out := make([]byte, 0, len(body)+len(cosmeticInject))
			out = append(out, body[:pos]...)
			out = append(out, cosmeticInject...)
			out = append(out, body[pos:]...)
			return out
		}
	}
	return append(append([]byte{}, cosmeticInject...), body...)
}
