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
	// Universal Filter Pack: MutationObserver — только addedNodes, не весь document
	js := `<script>(function(){
var SELS='` + jsSel + `';
var MARKS=['Реклама','Рекламное объявление','Advertisement','Sponsored'];
function hide(el){if(!el||!el.style)return;el.style.display='none';el.style.height='0';el.style.overflow='hidden';}
function hideSel(root){
	if(!root||!root.querySelectorAll)return;
	// сам addedNode может matches(SELS)
	if(root.nodeType===1&&root.matches&&root.matches(SELS))hide(root);
	var els=root.querySelectorAll(SELS);for(var i=0;i<els.length;i++)hide(els[i]);
}
function norm(t){return (t||'').replace(/\s+/g,' ').trim();}
function isAdSign(el){return el&&el.matches&&el.matches(SELS);}
function findMark(root){
	if(!root)return;
	var all=[];
	// сам addedNode может содержать текст маркера
	if(root.nodeType===1)all.push(root);
	if(root.querySelectorAll){
		var texts=root.querySelectorAll('span,div,p,a,small,em,i,b,strong,label,button');
		for(var i=0;i<texts.length;i++)all.push(texts[i]);
	}
	for(var i=0;i<all.length;i++){
		var t=norm(all[i].textContent);
		if(MARKS.indexOf(t)<0)continue;
		var el=all[i];
		var best=null;
		for(var up=0;up<6&&el.parentElement;up++){
			el=el.parentElement;
			var tag=(el.tagName||'').toUpperCase();
			if(tag==='BODY'||tag==='HTML'||tag==='MAIN'||tag==='ARTICLE')break;
			// приоритет: ancestor с ad-признаком
			if(isAdSign(el)){best=el;break;}
			var r=el.getBoundingClientRect();
			// реальный рекламный контейнер: достаточно большой, но не весь экран
			if(r.width>=200&&r.height>=80&&r.height<window.innerHeight*0.8){
				if(!best)best=el;
				break;
			}
		}
		if(best)hide(best);
	}
}
function scan(root){hideSel(root);findMark(root);}
// один полный проход при старте
scan(document.documentElement);
// дальше только addedNodes
var obs=new MutationObserver(function(muts){
	for(var m=0;m<muts.length;m++){
		var nodes=muts[m].addedNodes;
		if(!nodes)continue;
		for(var n=0;n<nodes.length;n++){
			scan(nodes[n]);
		}
	}
});
obs.observe(document.documentElement,{childList:true,subtree:true});
})();</script>`
	inject := "<style>" + css + "{display:none!important;visibility:hidden!important;height:0!important;min-height:0!important;max-height:0!important;overflow:hidden!important}</style>" + js
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
	var out []byte
	pos := 0
	for {
		idx := bytes.Index(lower[pos:], []byte("<meta"))
		if idx < 0 {
			out = append(out, body[pos:]...)
			break
		}
		absIdx := pos + idx
		end := absIdx
		for end < len(body) && body[end] != '>' {
			end++
		}
		if end >= len(body) {
			out = append(out, body[pos:]...)
			break
		}
		tag := lower[absIdx:end]
		// копируем всё до meta + сам meta (если не CSP)
		out = append(out, body[pos:absIdx]...)
		if !bytes.Contains(tag, []byte("content-security-policy")) {
			out = append(out, body[absIdx:end+1]...)
		}
		pos = end + 1
	}
	return out
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
