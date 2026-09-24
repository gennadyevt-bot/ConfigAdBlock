package mitm

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// assetDir — путь к assets (выставляется из JNI при старте движка)
var assetDir string

// extractSelectors - парсинг generic_cosmetic_rules.txt в список CSS selectors
func extractSelectors(dir string) []string {
	data, err := os.ReadFile(filepath.Join(dir, "generic_cosmetic_rules.txt"))
	if err != nil {
		return nil
	}
	var sel []string
	for _, line := range strings.Split(string(data), "\n") {
		l := strings.TrimSpace(line)
		if l == "" || strings.HasPrefix(l, "!") {
			continue
		}
		if strings.Contains(l, "##") {
			sel = append(sel, strings.SplitN(l, "##", 2)[1])
		} else {
			sel = append(sel, l)
		}
	}
	return sel
}

// SetAssetDir вызывается из Java перед стартом фильтрации
func SetAssetDir(dir string) {
	assetDir = dir
	cosmeticInject = buildCosmeticInject()
	count := len(extractSelectors(assetDir))
	if count == 0 {
		count = 6 // fallback
	}
	flowLog(fmt.Sprintf("GENERIC_COSMETIC_RULES count=%d", count))
}

// cosmeticInject собирается из assets/generic_cosmetic_rules.txt (universal V1).
// Опасные глобальные селекторы [class*=banner]/[id*=banner]/[class*=ad]/[class*=promo]
// удалены — они ломали обычные сайты.
var cosmeticInject = buildCosmeticInject()

func buildCosmeticInject() []byte {
	data, err := os.ReadFile(filepath.Join(assetDir, "generic_cosmetic_rules.txt"))
	if err != nil || len(data) == 0 {
		// fallback: только безопасные
		data = []byte("[data-ad-client]\n[data-ad-slot]\n[class*=\"adfox\"]\n[id*=\"adfox\"]\n[class*=\"adsbygoogle\"]\n[data-testid*=\"advert\"]\n[data-marker=\"advert\"]")
	}
	var sel []string
	for _, line := range strings.Split(string(data), "\n") {
		l := strings.TrimSpace(line)
		if l == "" || strings.HasPrefix(l, "!") {
			continue
		}
		// domain##selector или ##selector -> берём selector
		if strings.Contains(l, "##") {
			parts := strings.SplitN(l, "##", 2)
			sel = append(sel, parts[1])
		} else {
			// обычный CSS selector (например [data-ad-client])
			sel = append(sel, l)
		}
	}
	// safe fallback: если после parsing selectors=0, используем безопасный минимум
	if len(sel) == 0 {
		sel = []string{"[data-ad-client]", "[data-ad-slot]", "[class*=\"adfox\"]", "[class*=\"adsbygoogle\"]", "[data-testid*=\"advert\"]", "[data-marker=\"advert\"]"}
	}
	printGenericCosmeticCount := true
	_ = printGenericCosmeticCount
	css := strings.Join(sel, ",")
	jsSel := strings.Join(sel, ",")
	inject := "<style>" + css + "{display:none!important;visibility:hidden!important;height:0!important;min-height:0!important;max-height:0!important;overflow:hidden!important}</style><script>(function(){function k(){document.querySelectorAll('" + jsSel + "').forEach(function(e){e.style.display='none';e.style.height='0';e.style.overflow='hidden'})}k();new MutationObserver(k).observe(document.documentElement,{childList:true,subtree:true})})();</script>"
	return []byte(inject)
}

// filterHTML: text/html -> вставляем косметику после <head>.
// Сжатие (gzip) прозрачно распаковывается и упаковывается обратно.
// isHTML проверяет Content-Type на HTML
func isHTML(resp *http.Response) bool {
	ct := resp.Header.Get("Content-Type")
	return strings.Contains(ct, "text/html")
}

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
	// Universal Filter Pack: удаляем CSP (header + meta) перед inject
	resp.Header.Del("Content-Security-Policy")
	resp.Header.Del("Content-Security-Policy-Report-Only")
	mod := stripCSPMeta(raw)
	mod = injectAfterHead(mod)
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

// stripCSPMeta - удалить <meta http-equiv="Content-Security-Policy" ...> из HTML
func stripCSPMeta(body []byte) []byte {
	lower := bytes.ToLower(body)
	for {
		idx := bytes.Index(lower, []byte("<meta"))
		if idx < 0 {
			break
		}
		// найти конец тега
		end := idx
		for end < len(body) && body[end] != '>' {
			end++
		}
		if end >= len(body) {
			break
		}
		tag := lower[idx:end]
		if bytes.Contains(tag, []byte("content-security-policy")) {
			// удалить этот meta tag
			out := make([]byte, 0, len(body))
			out = append(out, body[:idx]...)
			out = append(out, body[end+1:]...)
			body = out
			lower = bytes.ToLower(body)
		} else {
			// пропустить этот meta
			lower = lower[end-idx:]
			body = body[end-idx:]
		}
	}
	return body
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
