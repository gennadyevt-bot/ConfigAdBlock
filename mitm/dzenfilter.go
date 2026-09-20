package mitm

// Delivery layer Этапа 2 (ветка content-filter-engine): ТОЧЕЧНАЯ
// доставка cosmetic CSS на dzen.ru. Никакого глобального MITM.
//
// Схема: DNS отдаёт для dzen.ru виртуальный адрес 10.0.0.3 -> маршрут
// 10.0.0.3/32 заворачивает TCP в движок -> здесь mini-MITM С ТЕМ ЖЕ
// пользовательским CA приложения: TLS с certForName(sni), HTTP/1.1,
// запрос к РЕАЛЬНОМУ dzen (IP резолвится ВНЕШНЕЙ цепочкой, не нашим
// DNS — иначе петля), в text/html инжектится CSS из правил косметики.
// Любая ошибка -> соединение просто закрывается (лог DZEN_*).

import (
	"bufio"
	"errors"
	"compress/gzip"
	"encoding/json"
	"crypto/sha256"
	"crypto/x509"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

const dzenFakeIP = "10.0.0.3"

// CSS из cosmetic_rules.txt (слой Kotlin держит полный парсер; для
// delivery-слоя достаточно зафиксированных селекторов первого кейса).
const dzenCSS = `[data-ad-type="direct"],
[data-ad-type="banner"],
div[aria-label="Лента Дзена"] article:has(> div[data-ad-type="direct"]),
div[id^="ad-"][class*="__isStretched"],
div[class*="MyTargetAdvert"],
.card-rtb,
[class*="adBox"],
div[data-testid="bottom-ad"],
div[class*="__advertItem "],
div[class^="desktop2--redesign-feed__"] div:has(> article[class*="--card-rtb__"]),
div[aria-label="Лента Дзена"] div + article[class*="--card-rtb__"],
div[class^="dzen-desktop--feed__itemWrap-"],
div[class^="dzen-desktop--"][class*="__cardWrapper-"] ~ article:has([class*="__adBox-"]),
div[class*="topContent"][class*="mobile__hasBanner"],
div[class*="news"] > div[class*="_banner_"],
.zenad-card-rtb,
.news-mt-advert,
.mg-advert > div[class*="loader"],
div[class*="Advert_"],
div[class^="BrandingAdvert"],
.news-advert-column,
.article-render-mobile__embed_embed-type_yandex-direct,
div[class^="dzen-desktop--banner-"],
div[class*="-corner-banner__"],
div[class^="content--dzen-pro-"] { display: none !important; }
`

func isDzenHost(h string) bool {
	h = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
	return h == "dzen.ru" || h == "www.dzen.ru" || h == "m.dzen.ru"
}

// dzenFakeDNSAnswer: A-запись -> 10.0.0.3; AAAA -> NOERROR пустой
// (клиент возьмёт наш A и пойдёт через фильтр).
func dzenFakeDNSAnswer(query []byte) []byte {
	if len(query) < 12 {
		return nil
	}
	i := 12
	for i < len(query) {
		l := int(query[i])
		i++
		if l == 0 {
			break
		}
		if l > 63 {
			return nil
		}
		i += l
	}
	if i+4 > len(query) {
		return nil
	}
	qtype := int(query[i])<<8 | int(query[i+1])
	i += 4
	resp := make([]byte, 12)
	copy(resp, query[:2])
	resp[2] = 0x81 // QR|RD
	resp[3] = 0x80 // RA, RCODE=0
	if qtype == 1 {
		resp[7] = 1 // ANCOUNT=1
	}
	resp = append(resp, query[12:i]...)
	if qtype == 1 {
		resp = append(resp, 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 10, 0, 0, 3)
	}
	return resp
}

// resolveRealIP: реальный адрес dzen через ВНЕШНЮЮ цепочку resolveDNS
// (DoT/DoH/UDP), НЕ через наш UDP-DNS (иначе ответили бы 10.0.0.3).
func resolveRealIP(host string) (string, error) {
	q := make([]byte, 0, 64)
	q = append(q, 0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	for _, part := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		q = append(q, byte(len(part)))
		q = append(q, part...)
	}
	q = append(q, 0, 0, 1, 0, 1)
	ans, err := resolveDNS(q)
	if err != nil {
		return "", err
	}
	return firstAFromDNS(ans)
}

func firstAFromDNS(ans []byte) (string, error) {
	if len(ans) < 12 {
		return "", fmt.Errorf("short dns answer")
	}
	i := 12
	skipName := func() {
		for i < len(ans) {
			l := int(ans[i])
			if l == 0 {
				i++
				return
			}
			if l&0xC0 == 0xC0 {
				i += 2
				return
			}
			i += 1 + l
		}
	}
	qd := int(ans[4])<<8 | int(ans[5])
	for k := 0; k < qd; k++ {
		skipName()
		i += 4
	}
	an := int(ans[6])<<8 | int(ans[7])
	for k := 0; k < an && i+10 <= len(ans); k++ {
		skipName()
		if i+10 > len(ans) {
			break
		}
		typ := int(ans[i])<<8 | int(ans[i+1])
		rdlen := int(ans[i+8])<<8 | int(ans[i+9])
		i += 10
		if typ == 1 && rdlen == 4 && i+4 <= len(ans) {
			return fmt.Sprintf("%d.%d.%d.%d", ans[i], ans[i+1], ans[i+2], ans[i+3]), nil
		}
		i += rdlen
	}
	return "", fmt.Errorf("no A record")
}

func dzenInjectCSS(html string) string {
	style := "<style data-cablock>\n" + dzenCSS + "</style>"
	script := `<script data-cablock>(function(){
var sels='[data-ad-type="direct"],[data-ad-type="banner"],[data-ad-type="rtb"],.card-rtb,[class*="adBox"],[class*="MyTargetAdvert"],[class*="advertItem"],[data-testid="bottom-ad"],div[class*="topContent"][class*="mobile__hasBanner"],div[class*="news"] > div[class*="_banner_"],.zenad-card-rtb,.news-mt-advert,.mg-advert > div[class*="loader"],div[class*="Advert_"],div[class^="BrandingAdvert"],.news-advert-column,.article-render-mobile__embed_embed-type_yandex-direct,div[class^="dzen-desktop--banner-"],div[class*="-corner-banner__"],div[class^="content--dzen-pro-"]';
var diagSent=0,iframeSent=0,iframeSeen={},shadowSeen=[],shadowCount=0;
function sendDiag(sig){
  if(diagSent>=6)return;
  if(!sig||sig.length>1000)return;
  diagSent++;
  try{fetch('/__configadblock_diag?d='+encodeURIComponent(sig),{credentials:'omit',cache:'no-store'}).catch(function(){});}catch(_){}
}
function sendIframe(host){
  if(iframeSent>=10)return;
  if(!host||host.length>80)return;
  if(iframeSeen[host])return;
  iframeSeen[host]=1;iframeSent++;
  try{fetch('/__configadblock_diag?d='+encodeURIComponent('IFRAME host='+host),{credentials:'omit',cache:'no-store'}).catch(function(){});}catch(_){}
}
function sigOf(e){
  var parts=[],n=e;
  for(var k=0;k<7&&n;k++){
    var s=n.tagName||'';
    if(n.id)s+='#'+n.id;
    var c=(n.className&&n.className.toString)?n.className.toString():'';
    if(c)s+='.'+c.split(' ').slice(0,4).join('.');
    if(s.length>70)s=s.slice(0,70);
    parts.push(s);
    n=n.parentElement;
  }
  return parts.join(' < ');
}
function rmSel(root){
  if(!root.querySelectorAll)return;
  if(root.matches&&root.matches(sels))root.remove();
  root.querySelectorAll(sels).forEach(function(e){e.remove();});
}
function hasT(root,t){return (root.textContent||'').indexOf(t)>=0;}
var ADLABEL=/^\s*Реклама(?:\s+\d+\+)?\s*$/i;
function rmLabel(root){
  if(!root.querySelectorAll)return;
  var all=(root.matches&&root.matches('*'))?[root]:[];
  root.querySelectorAll('*').forEach(function(e){all.push(e);});
  for(var k=0;k<all.length;k++){
    var e=all[k];
    if(!ADLABEL.test(e.textContent||''))continue;
    sendDiag(sigOf(e));
    var n=e,appHit=false;
    for(var up=0;up<8&&n&&n.parentElement;up++){
      n=n.parentElement;
      var s=((n.className&&n.className.toString)?n.className.toString():'')+' '+((n.id)||'');
      var cls=/advert|advertising|banner|adbox|rtb|zenad|brandingadvert/i.test(s);
      var triple=hasT(n,'Реклама')&&hasT(n,'Скрыть')&&hasT(n,'Пожаловаться');
      // 226: app-install/native карточка: метка + Рейтинг и отзывы + О приложении
      var app=hasT(n,'Рейтинг и отзывы')&&hasT(n,'О приложении')&&hasT(n,'Реклама');
      if(app&&!appHit){appHit=true;sendDiag(sigOf(n));}
      if(triple)sendDiag(sigOf(n));
      if(cls||triple||app){
        if(app){try{fetch('/__configadblock_diag?d='+encodeURIComponent('APPAD'),{credentials:'omit'}).catch(function(){});}catch(_){}}
        n.remove();break;
      }
    }
  }
}
function emptyAdWrap(root){
  if(!root.querySelectorAll)return;
  root.querySelectorAll('div').forEach(function(d){
    var s=((d.className&&d.className.toString)?d.className.toString():'')+' '+(d.id||'');
    if(!/advert|banner|adbox|rtb|zenad|loader|skeleton/i.test(s))return;
    if((d.textContent||'').trim()!=='')return;
    if(d.querySelector('img,video,article,[role="article"]'))return;
    d.remove();
  });
}
function scanIframes(root){
  if(!root.querySelectorAll)return;
  root.querySelectorAll('iframe').forEach(function(f){
    var h='';
    try{var u=new URL(f.src||'',location.href);h=u.hostname||'';}catch(_){}
    if(h)sendIframe(h);
    var same=false;
    try{var doc=f.contentDocument;if(doc&&doc.documentElement){same=true;scan(doc.documentElement);}}catch(_){}
  });
}
function scanShadows(root){
  if(!root.querySelectorAll)return;
  root.querySelectorAll('*').forEach(function(e){
    if(shadowCount>=20)return;
    var sr=null;
    try{sr=e.shadowRoot;}catch(_){}
    if(sr&&sr.documentElement!==undefined||sr){
      var key=sigOf(e);
      if(shadowSeen.indexOf(key)<0){
        shadowSeen.push(key);shadowCount++;
        scan(sr);
        try{
          new MutationObserver(function(ms){ms.forEach(function(m){if(m.addedNodes)m.addedNodes.forEach(function(nd){if(nd.nodeType===1)scan(nd);});});}).observe(sr,{childList:true,subtree:true});
        }catch(_){}
      }
    }
  });
}
function scan(root){
  try{
    rmSel(root);rmLabel(root);emptyAdWrap(root);
    scanIframes(root);scanShadows(root);
  }catch(_){}
}
scan(document);
[0,250,750,1500,3000].forEach(function(t){setTimeout(function(){scan(document);},t);});
new MutationObserver(function(ms){
  ms.forEach(function(m){
    if(!m.addedNodes)return;
    m.addedNodes.forEach(function(nd){if(nd.nodeType===1)scan(nd);});
  });
}).observe(document.documentElement,{childList:true,subtree:true});
})();</script>`
	low := strings.ToLower(html)
	idx := strings.Index(low, "</head>")
	if idx > 0 {
		return html[:idx] + style + "\n" + script + "\n" + html[idx:]
	}
	return style + "\n" + script + "\n" + html
}

// handleDzenMITM — mini-MITM ТОЛЬКО для dzen.ru.
// handleDzenMITM - собственный selective content-MITM для dzen (2.0.7/209).
// Вызывается из SOCKS5 с УЖЕ прочитанным raw ClientHello - replay через
// sniffConn. Fail-open: отказ от сертификата/любая TLS-ошибка -> sni в
// bypassCache, следующий reconnect этого sni идёт DIRECT. Никакого goproxy.
func handleDzenMITM(conn net.Conn, sni string, raw []byte) (handled bool, ok bool) {
	// 220: ONE-SHOT bypass - этот вызов разрешаем direct, следующий снова MITM
	if bypassConsumeOne(sni) {
		flowLog("DZEN_BYPASS_ONCE_CONSUMED sni=" + sni)
		return false, false
	}
	flowLog("DZEN_MITM_BEGIN host=" + sni)
	// Resolve the leaf before consuming/writing TLS or taking ownership.
	leaf, err := certForName(sni)
	if err != nil {
		flowLog("DZEN_CA_FAIL host=" + sni + " err=" + err.Error())
		flowLog("DZEN_BYPASS_DIRECT sni=" + sni)
		return false, false
	}
	flowLog("DZEN_CA_READY host=" + sni)
	// 2.0.12: фактическая диагностика цепочки ДО handshake
	dzenDiagChain(sni, leaf)
	handled = true
	defer func() {
		if r := recover(); r != nil {
			flowLog(fmt.Sprintf("DZEN_MITM_FAIL panic:%v", r))
		}
		// 218: БЕЗ blanket cacheBypass - ошибка одного соединения
		// (timeout/EOF/resolve/upstream) не отключает фильтр для sni.
		// В bypass попадаем ТОЛЬКО при реальном TLS trust rejection.
		_ = conn.Close()
	}()
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
		Certificates: []tls.Certificate{*leaf},
	}
	tlsConn := tls.Server(&sniffConn{Conn: conn, prefix: raw}, cfg)
	_ = tlsConn.SetDeadline(time.Now().Add(20 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		// 218: bypass ТОЛЬКО при реальном отказе браузера от сертификата.
		// timeout/EOF/abort после TLS-слёта - обычная ошибка соединения,
		// reconnect должен снова попытать MITM.
		es := err.Error()
		certReject := strings.Contains(es, "unknown certificate") ||
			strings.Contains(es, "bad certificate") ||
			strings.Contains(es, "certificate required") ||
			strings.Contains(es, "certificate verify failed")
		if certReject {
			// 220: НЕ session-wide bypass - только один следующий reconnect
			bypassOnceSet(sni)
			flowLog("DZEN_TLS_REJECT host=" + sni + " err=" + es)
			flowLog("DZEN_BYPASS_ONCE_SET sni=" + sni + " reason=tls_reject")
		} else {
			flowLog("DZEN_TLS_FAIL host=" + sni + " err=" + es)
		}
		return true, false
	}
	_ = tlsConn.SetDeadline(time.Now().Add(30 * time.Second))
	flowLog("DZEN_TLS_OK sni=" + sni)
	// 218: успешный TLS снимает возможный старый transient bypass этого sni
	unBypassHost(sni)

	br := bufio.NewReader(tlsConn)
	reqs := 0
	flowLog("DZEN_CONN_OPEN sni=" + sni)
	for {
		// 221: idle/preconnect timeout - НЕ ошибка MITM, а нормальное
		// закрытие speculative/preconnect-соединения. 8 с простоя.
		_ = tlsConn.SetDeadline(time.Now().Add(8 * time.Second))
		req, err := http.ReadRequest(br)
		if err != nil {
			var ne net.Error
			if errors.Is(err, io.EOF) || (errors.As(err, &ne) && ne.Timeout()) {
				flowLog(fmt.Sprintf("DZEN_CONN_IDLE_CLOSE sni=%s requests=%d", sni, reqs))
				return true, true // benign: не считается MITM-ошибкой
			}
			flowLog(fmt.Sprintf("DZEN_CONN_CLOSE sni=%s requests=%d reason=read:%v", sni, reqs, err))
			return true, reqs > 0
		}
		reqs++
		flowLog(fmt.Sprintf("DZEN_REQ n=%d method=%s path=%s", reqs, req.Method, req.URL.Path))

		// 225: локальный diag-endpoint - DOM-сигнатуры не уходят на dzen.ru
		if req.URL.Path == "/__configadblock_diag" {
			q := req.URL.Query().Get("d")
			if len(q) > 1000 {
				q = q[:1000]
			}
			if strings.HasPrefix(q, "IFRAME host=") {
				flowLog("DZEN_IFRAME_DIAG host=" + strings.TrimPrefix(q, "IFRAME host="))
			} else if q == "APPAD" {
				flowLog("DZEN_APP_AD_REMOVED")
			} else if q != "" {
				flowLog("DZEN_DOM_DIAG " + q)
			}
			dr := &http.Response{StatusCode: 204, Status: "204 No Content", Proto: "HTTP/1.1",
				ProtoMajor: 1, ProtoMinor: 1, Header: make(http.Header),
				Body: io.NopCloser(strings.NewReader("")), ContentLength: 0, Close: false, Request: req}
			_ = dr.Write(tlsConn)
			continue
		}
		// Route only the selective host authenticated by the client SNI.
		upstreamHost := sni
		if req.Host != "" && !strings.EqualFold(req.Host, sni) && !strings.EqualFold(req.Host, net.JoinHostPort(sni, "443")) {
			flowLog(fmt.Sprintf("DZEN_CONN_CLOSE sni=%s requests=%d reason=host-mismatch", sni, reqs))
			return true, reqs > 0
		}
		ip, err := resolveRealIP(upstreamHost)
		if err != nil {
			flowLog("DZEN_MITM_POST_TLS_FAIL sni=" + sni + " stage=resolve err=" + err.Error())
			continue // апстрим не рвёт клиентскую TLS-сессию
		}
		up, err := dialTCP(net.JoinHostPort(ip, "443"))
		if err != nil {
			flowLog("DZEN_MITM_POST_TLS_FAIL sni=" + sni + " stage=updial err=" + err.Error())
			continue
		}
		upTLS := tls.Client(up, &tls.Config{ServerName: upstreamHost, MinVersion: tls.VersionTLS12})
		_ = upTLS.SetDeadline(time.Now().Add(20 * time.Second))
		if err := upTLS.Handshake(); err != nil {
			_ = up.Close()
			flowLog("DZEN_MITM_POST_TLS_FAIL sni=" + sni + " stage=uptls err=" + err.Error())
			continue
		}
		_ = upTLS.SetDeadline(time.Now().Add(30 * time.Second))
		_ = tlsConn.SetDeadline(time.Now().Add(30 * time.Second))

		outReq := new(http.Request)
		*outReq = *req
		outReq.URL.Scheme = "https"
		outReq.URL.Host = upstreamHost
		outReq.RequestURI = ""
		outReq.Close = true // upstream открываем на каждый request - keep-alive не нужен
		outReq.Header = req.Header.Clone()
		outReq.Header.Del("Proxy-Connection")
		outReq.Header.Del("Accept-Encoding") // иначе br/gzip-тело не проинжектить
		if err := outReq.Write(upTLS); err != nil {
			_ = up.Close()
			flowLog("DZEN_MITM_POST_TLS_FAIL sni=" + sni + " reqwrite:" + err.Error())
			continue
		}
		_, _ = io.Copy(io.Discard, req.Body)
		_ = req.Body.Close()
		resp, err := http.ReadResponse(bufio.NewReader(upTLS), outReq)
		if err != nil {
			_ = up.Close()
			flowLog("DZEN_MITM_POST_TLS_FAIL sni=" + sni + " upread:" + err.Error())
			continue
		}
		flowLog(fmt.Sprintf("DZEN_RESP n=%d status=%s path=%s", reqs, resp.Status, req.URL.Path))
		flowLog(fmt.Sprintf("DZEN_RESPONSE host=%s method=%s path=%s status=%s ct=%s len=%d",
			upstreamHost, req.Method, req.URL.Path, resp.Status,
			strings.ToLower(resp.Header.Get("Content-Type")), resp.ContentLength))
		if err := filterDzenResponse(resp, req.URL.Path); err != nil {
			resp.Body.Close()
			_ = up.Close()
			flowLog("DZEN_MITM_POST_TLS_FAIL sni=" + sni + " body:" + err.Error())
			continue
		}
		// 221: клиентская TLS-сессия НЕ рвётся после каждого ответа
		resp.Close = false
		if err := resp.Write(tlsConn); err != nil {
			resp.Body.Close()
			_ = up.Close()
			flowLog(fmt.Sprintf("DZEN_CONN_CLOSE sni=%s requests=%d reason=respwrite:%v", sni, reqs, err))
			return true, reqs > 0
		}
		resp.Body.Close()
		_ = up.Close()
	}
}
// Keep the body reader consistent with any rewritten content and length.
func filterDzenResponse(resp *http.Response, reqPath string) error {
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	// 216: для Дзена снимаем CSP - иначе inline <script> косметики заблокирован
	resp.Header.Del("Content-Security-Policy")
	resp.Header.Del("Content-Security-Policy-Report-Only")
	if strings.Contains(ct, "text/html") {
		flowLog("DZEN_HTML_RESPONSE path=" + reqPath + " enc=" + resp.Header.Get("Content-Encoding"))
	}
	if strings.Contains(ct, "text/html") && (resp.Header.Get("Content-Encoding") == "" || resp.Header.Get("Content-Encoding") == "identity") {
		const limit = 16 * 1024 * 1024
		body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
		if err != nil {
			return err
		}
		if len(body) <= limit {
			body = []byte(dzenInjectCSS(string(body)))
			flowLog("DZEN_COSMETIC_RULESET=226")
		flowLog("DZEN_COSMETIC_INJECTED path=" + reqPath + " ruleset=226")
			resp.Body = io.NopCloser(bytes.NewReader(body))
			resp.ContentLength = int64(len(body))
			resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
			resp.Header.Del("Transfer-Encoding")
			resp.Header.Del("Content-Security-Policy")
			resp.Header.Del("Content-Security-Policy-Report-Only")
			resp.Header.Del("ETag")
			resp.TransferEncoding = nil
			flowLog("DZEN_HTML_FILTERED bytes=" + strconv.Itoa(len(body)))
		} else {
			// Preserve large responses instead of silently truncating them.
			resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), resp.Body))
			flowLog("DZEN_HTML_SKIP oversized")
		}
	}

	// 2.0.13/215: JSON-фильтрация ленты Дзена (рекламные элементы
	// удаляются из массивов целиком -> пустых контейнеров не остаётся).
	// Fail-open: любая ошибка -> оригинальный body без изменений.
	// 217: структурная диагностика JSON (только ключи, без содержимого)
	if strings.Contains(ct, "application/json") && (resp.Header.Get("Content-Encoding") == "" || resp.Header.Get("Content-Encoding") == "identity") {
		if jb, jerr := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024)); jerr == nil {
			resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(jb), resp.Body))
			dzenDiagJSON(reqPath, jb)
		}
	}
	if strings.Contains(ct, "application/json") {
		const limit = 16 * 1024 * 1024
		body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
		if err != nil {
			return err
		}
		final := body
		if len(body) > limit {
			resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), resp.Body))
			flowLog("DZEN_JSON_SKIP oversized")
			return nil
		}
		enc := strings.ToLower(resp.Header.Get("Content-Encoding"))
		switch enc {
		case "", "identity":
			filtered, removed, ferr := dzenFilterJSON(body, reqPath)
			if ferr != nil {
				flowLog("DZEN_JSON_SKIP parse-fail")
			} else if removed > 0 {
				final = filtered
				flowLog(fmt.Sprintf("DZEN_JSON_FILTERED path=%s removed=%d", reqPath, removed))
			}
		case "gzip":
			raw, e1 := dzenGunzip(body)
			if e1 != nil {
				flowLog("DZEN_JSON_SKIP gunzip:" + e1.Error())
			} else {
				filtered, removed, ferr := dzenFilterJSON(raw, reqPath)
				switch {
				case ferr != nil:
					flowLog("DZEN_JSON_SKIP parse-fail")
				case removed == 0:
				default:
					if out, e2 := dzenGzip(filtered); e2 != nil {
						flowLog("DZEN_JSON_SKIP regzip:" + e2.Error())
					} else {
						final = out
						flowLog(fmt.Sprintf("DZEN_JSON_FILTERED path=%s removed=%d", reqPath, removed))
					}
				}
			}
		default:
			// br/deflate без поддержки - НЕ ломаем, отдаём как есть
			flowLog("DZEN_FILTER_SKIP encoding=" + enc)
		}
		resp.Body = io.NopCloser(bytes.NewReader(final))
		resp.ContentLength = int64(len(final))
		resp.Header.Set("Content-Length", strconv.Itoa(len(final)))
		resp.Header.Del("Transfer-Encoding")
		resp.TransferEncoding = nil
	}

	return nil
}


// dzenDiagChain - фактическая проверка TLS-цепочки Дзена ДО handshake:
// SAN, issuer, подпись ТЕКУЩИМ CA, EKU, срок + длина/хэши реально
// отправляемой цепочки. Ответ на вопрос "почему unknown certificate".
func dzenDiagChain(host string, cert *tls.Certificate) {
	chainLen := len(cert.Certificate)
	flowLog(fmt.Sprintf("DZEN_CHAIN_LEN=%d", chainLen))
	for i, der := range cert.Certificate {
		fp := sha256.Sum256(der)
		flowLog(fmt.Sprintf("DZEN_CHAIN_%d_SHA256=%X", i, fp[:8]))
	}
	if chainLen == 0 {
		flowLog("LEAF_HOST=" + host + " LEAF_MISSING=true")
		return
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		flowLog("LEAF_HOST=" + host + " LEAF_PARSE_FAIL=" + err.Error())
		return
	}
	sanOK := leaf.VerifyHostname(host) == nil
	cur := currentMITMCA()
	issuerMatch := cur != nil && leaf.Issuer.String() == cur.Subject.String()
	sigOK := false
	if cur != nil {
		sigOK = leaf.CheckSignatureFrom(cur) == nil
	}
	serverAuth := false
	for _, u := range leaf.ExtKeyUsage {
		if u == x509.ExtKeyUsageServerAuth {
			serverAuth = true
		}
	}
	now := time.Now()
	valid := now.After(leaf.NotBefore) && now.Before(leaf.NotAfter)
	flowLog(fmt.Sprintf("LEAF_HOST=%s SAN_OK=%v ISSUER_MATCH=%v SIG_OK=%v SERVER_AUTH=%v VALID=%v IsCA=%v",
		host, sanOK, issuerMatch, sigOK, serverAuth, valid, leaf.IsCA))
}


// --- 2.0.13/215: JSON-фильтрация Дзена -------------------------------------

var dzenAdKeyHints = []string{"advert", "banner", "adfox", "nativead", "promo",
	"commercial", "socialad", "yandexad", "zen_ad", "ad_type", "adtype", "isad", "advertisement"}

func dzenGunzip(b []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	return io.ReadAll(io.LimitReader(zr, 64*1024*1024))
}

func dzenGzip(b []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// dzenFilterJSON парсит JSON, логирует найденные рекламные маркеры и
// удаляет рекламные элементы массивов. Возвращает nil,0,nil если нечего
// удалять. Любая ошибка -> оригинальный body (fail-open снаружи).
func dzenBoolFlag(m map[string]interface{}, key string) string {
	if m == nil {
		return "missing"
	}
	v, ok := m[key]
	if !ok {
		return "missing"
	}
	b, ok := v.(bool)
	if !ok {
		return "missing"
	}
	if b {
		return "true"
	}
	return "false"
}

func dzenCountElems(v interface{}) int {
	switch t := v.(type) {
	case []interface{}:
		return len(t)
	case map[string]interface{}:
		return len(t)
	}
	return 1
}

// dzenFilterMorePath - 219: точечная фильтрация /api/web/v1/more.
// Только здесь: top-level ad_items удаляется целиком, items[] выкидываются
// ТОЛЬКО при isNativeAds==true / isPromoPublication==true (не по наличию ключа).
func dzenFilterMorePath(root *interface{}, reqPath string) (removed int, adItemsRemoved int, cardsRemoved int) {
	if reqPath != "/api/web/v1/more" {
		return 0, 0, 0
	}
	m, ok := (*root).(map[string]interface{})
	if !ok {
		return 0, 0, 0
	}
	if ai, exists := m["ad_items"]; exists && !dzenEmptyVal(ai) {
		n := dzenCountElems(ai)
		delete(m, "ad_items")
		removed++
		adItemsRemoved = n
		flowLog(fmt.Sprintf("DZEN_JSON_FIELD_REMOVED path=%s key=ad_items count=%d", reqPath, n))
	}
	if arr, ok := m["items"].([]interface{}); ok {
		kept := arr[:0]
		for i, el := range arr {
			em, _ := el.(map[string]interface{})
			ina := dzenBoolFlag(em, "isNativeAds")
			ipp := dzenBoolFlag(em, "isPromoPublication")
			plEmpty := true
			if pl, ok2 := em["promoLabel"].(map[string]interface{}); ok2 {
				plEmpty = len(pl) == 0
			}
			flowLog(fmt.Sprintf("DZEN_ITEM_FLAGS index=%d isNativeAds=%s isPromoPublication=%s promoLabelEmpty=%v",
				i, ina, ipp, plEmpty))
			reason := ""
			if ina == "true" {
				reason = "isNativeAds=true"
			} else if ipp == "true" {
				reason = "isPromoPublication=true"
			}
			if reason != "" {
				cardsRemoved++
				removed++
				flowLog(fmt.Sprintf("DZEN_JSON_CARD_REMOVED path=.items[%d] reason=%s id=%s", i, reason, dzenElemID(em)))
				continue
			}
			kept = append(kept, el)
		}
		m["items"] = kept
	}
	return removed, adItemsRemoved, cardsRemoved
}

func dzenFilterJSON(body []byte, reqPath string) ([]byte, int, error) {
	var v interface{}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil, 0, err
	}
	// 219: точечная обработка ленты Дзен
	mr, adN, cardN := dzenFilterMorePath(&v, reqPath)
	removed, markers := dzenScrub(&v, "")
	removed += mr
	if len(markers) == 0 {
		flowLog("DZEN_JSON_NO_AD_MARKERS")
	} else {
		seen := make(map[string]bool)
		n := 0
		for _, m := range markers {
			if !seen[m] && n < 12 {
				seen[m] = true
				n++
				flowLog("DZEN_JSON_AD_FOUND " + m)
			}
		}
	}
	if removed == 0 {
		return nil, 0, nil
	}
	out, err := json.Marshal(v)
	if err != nil {
		return nil, 0, err
	}
	if adN > 0 || cardN > 0 {
		flowLog(fmt.Sprintf("DZEN_FEED_FILTER path=%s adItemsRemoved=%d cardsRemoved=%d",
			reqPath, adN, cardN))
	}
	return out, removed, nil
}

func dzenIsAdKey(kl string) bool {
	for _, a := range dzenAdKeyHints {
		if kl == a || strings.Contains(kl, a) {
			return true
		}
	}
	return false
}

func dzenIsAdElement(m map[string]interface{}) bool {
	for k, v := range m {
		kl := strings.ToLower(k)
		switch kl {
		case "isad", "is_ad":
			if b, ok := v.(bool); ok && b {
				return true
			}
		case "adtype", "ad_type", "type":
			if s, ok := v.(string); ok && dzenAdTypeVal(s) {
				return true
			}
		case "adfox", "nativead", "native_ad", "zen_ad", "advertising", "advertisement":
			return true
		}
	}
	return false
}

func dzenAdTypeVal(s string) bool {
	s = strings.ToLower(s)
	return s == "ad" || strings.Contains(s, "direct") || strings.Contains(s, "banner") ||
		strings.Contains(s, "promo") || strings.Contains(s, "advert") || strings.Contains(s, "native")
}

func dzenElemID(m map[string]interface{}) string {
	for _, k := range []string{"id", "feedId", "documentId", "rid", "blockId"} {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				if len(s) > 16 {
					return s[:16]
				}
				return s
			}
		}
	}
	return "-"
}

// dzenContainsStrongAdSignal - СИЛЬНЫЕ рекламные признаки во всём subtree
// карточки (включая вложенные data/content/meta). Консервативно: generic
// "promo" и любое вхождение "ad" НЕ считаются рекламой.
func dzenContainsStrongAdSignal(v interface{}, path string) (bool, string, string) {
	switch t := v.(type) {
	case map[string]interface{}:
		for k, val := range t {
			kl := strings.ToLower(k)
			p := path + "." + k
			switch kl {
			case "isad", "is_ad":
				if b, ok := val.(bool); ok && b {
					return true, kl + "=true", p
				}
			case "adtype", "ad_type":
				if s, ok := val.(string); ok && dzenStrongAdType(s) {
					return true, kl + "=" + s, p
				}
			case "adfox", "nativead", "native_ad", "advertisement", "advertising",
				"yandexad", "yandex_ad", "zen_ad", "direct":
				if !dzenEmptyVal(val) {
					return true, "key:" + kl, p
				}
			}
			if s, ok := val.(string); ok && dzenStrongAdLabel(s) {
				return true, "label:" + s, p
			}
			if hit, r, mp := dzenContainsStrongAdSignal(val, p); hit {
				return true, r, mp
			}
		}
	case []interface{}:
		for i, el := range t {
			if hit, r, mp := dzenContainsStrongAdSignal(el, fmt.Sprintf("%s[%d]", path, i)); hit {
				return true, r, mp
			}
		}
	case string:
		if dzenStrongAdLabel(t) {
			return true, "label:" + t, path
		}
	}
	return false, "", ""
}

func dzenStrongAdType(s string) bool {
	switch strings.ToLower(s) {
	case "ad", "direct", "banner", "advertising", "advertisement", "native", "nativead", "rtb":
		return true
	}
	return false
}

func dzenStrongAdLabel(s string) bool {
	sl := strings.ToLower(s)
	if strings.Contains(sl, "реклама") || strings.Contains(sl, "соцреклама") ||
		strings.Contains(sl, "advertisement") {
		return true
	}
	return false
}

func dzenEmptyVal(v interface{}) bool {
	switch t := v.(type) {
	case nil:
		return true
	case string:
		return t == ""
	case bool:
		return !t
	case map[string]interface{}:
		return len(t) == 0
	case []interface{}:
		return len(t) == 0
	}
	return false
}

// dzenScrub: элементы массивов с СИЛЬНЫМ сигналом в любом месте subtree
// удаляются ЦЕЛИКОМ (контейнер схлопывается); очевидные рекламные поля в
// map удаляются отдельно. Маркеры в ключах логируются как раньше.
func dzenScrub(node *interface{}, path string) (int, []string) {
	removed := 0
	var markers []string
	switch t := (*node).(type) {
	case map[string]interface{}:
		for k, val := range t {
			kl := strings.ToLower(k)
			if dzenIsAdKey(kl) {
				markers = append(markers, fmt.Sprintf("key=%s path=%s type=%T", k, path+"."+k, val))
			}
			// отдельный очевидный рекламный payload-объект в map
			if dzenIsAdObjectKey(kl) && !dzenEmptyVal(val) {
				delete(t, k)
				removed++
				flowLog(fmt.Sprintf("DZEN_JSON_FIELD_REMOVED key=%s path=%s", k, path+"."+k))
				continue
			}
			r, m := dzenScrub(&val, path+"."+k)
			t[k] = val
			removed += r
			markers = append(markers, m...)
		}
	case []interface{}:
		kept := t[:0]
		for i, el := range t {
			// 216: СНАЧАЛА глубокая проверка ВСЕГО subtree карточки
			if hit, reason, mpath := dzenContainsStrongAdSignal(el, fmt.Sprintf("%s[%d]", path, i)); hit {
				removed++
				flowLog(fmt.Sprintf("DZEN_JSON_CARD_REMOVED path=%s[%d] reason=%s markerPath=%s id=%s",
					path, i, reason, mpath, dzenElemIDOf(el)))
				continue
			}
			var elv interface{} = el
			r, m := dzenScrub(&elv, fmt.Sprintf("%s[%d]", path, i))
			kept = append(kept, elv)
			removed += r
			markers = append(markers, m...)
		}
		*node = kept
	}
	return removed, markers
}

func dzenIsAdObjectKey(kl string) bool {
	switch kl {
	case "adfox", "nativead", "native_ad", "advertisement", "advertising",
		"yandexad", "yandex_ad", "zen_ad":
		return true
	}
	return false
}

func dzenElemIDOf(v interface{}) string {
	if m, ok := v.(map[string]interface{}); ok {
		return dzenElemID(m)
	}
	return "-"
}


// --- 2.0.15/217: структурная диагностика JSON (только ключи) ---------------

var dzenSuspectKeys = []string{"feed", "items", "cards", "publications", "recommendations",
	"content", "blocks", "stories", "entries", "documents", "zen", "rtb", "banner",
	"advert", "advertising", "native", "direct"}

// dzenDiagJSON логирует СТРУКТУРУ ответа: top-level ключи и объекты с
// подозрительными ключами. Ни одно значение не пишется - только имена ключей.
func dzenDiagJSON(reqPath string, body []byte) {
	var v interface{}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return
	}
	if m, ok := v.(map[string]interface{}); ok {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if len(keys) > 24 {
			keys = keys[:24]
		}
		flowLog("DZEN_JSON_KEYS path=" + reqPath + " keys=" + strings.Join(keys, ","))
	}
	dzenSuspectWalk(v, reqPath, reqPath, 0)
}

func dzenSuspectWalk(node interface{}, reqPath, jpath string, depth int) {
	if depth > 4 {
		return
	}
	switch t := node.(type) {
	case map[string]interface{}:
		var hits []string
		for k := range t {
			kl := strings.ToLower(k)
			for _, s := range dzenSuspectKeys {
				if kl == s || strings.Contains(kl, s) {
					hits = append(hits, k)
					break
				}
			}
		}
		if len(hits) > 0 {
			sort.Strings(hits)
			if len(hits) > 10 {
				hits = hits[:10]
			}
			flowLog("DZEN_JSON_SUSPECT path=" + reqPath + " jsonPath=" + jpath + " keys=" + strings.Join(hits, ","))
		}
		for k, val := range t {
			dzenSuspectWalk(val, reqPath, jpath+"."+k, depth+1)
		}
	case []interface{}:
		if len(t) > 3 {
			dzenSuspectWalk(t[0], reqPath, jpath+"[0]", depth+1)
		} else {
			for i, el := range t {
				dzenSuspectWalk(el, reqPath, fmt.Sprintf("%s[%d]", jpath, i), depth+1)
			}
		}
	}
}
