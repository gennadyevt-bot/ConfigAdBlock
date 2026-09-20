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
div[data-testid="bottom-ad"],
div[class*="__advertItem "],
div[class^="desktop2--redesign-feed__"] div:has(> article[class*="--card-rtb__"]),
div[aria-label="Лента Дзена"] div + article[class*="--card-rtb__"],
div[class^="dzen-desktop--feed__itemWrap-"],
div[class^="dzen-desktop--"][class*="__cardWrapper-"] ~ article:has([class*="__adBox-"]) { display: none !important; }
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
	low := strings.ToLower(html)
	i := strings.Index(low, "</head>")
	if i > 0 {
		return html[:i] + style + "\n" + html[i:]
	}
	return style + "\n" + html
}

// handleDzenMITM — mini-MITM ТОЛЬКО для dzen.ru.
// handleDzenMITM - собственный selective content-MITM для dzen (2.0.7/209).
// Вызывается из SOCKS5 с УЖЕ прочитанным raw ClientHello - replay через
// sniffConn. Fail-open: отказ от сертификата/любая TLS-ошибка -> sni в
// bypassCache, следующий reconnect этого sni идёт DIRECT. Никакого goproxy.
func handleDzenMITM(conn net.Conn, sni string, raw []byte) (handled bool, ok bool) {
	if isBypassed(sni, "") {
		flowLog("DZEN_BYPASS_DIRECT sni=" + sni)
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
		// Once TLS bytes were sent, direct relay is only safe on reconnect.
		if !ok {
			cacheBypass(sni)
		}
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
		// клиент не принял сертификат/обрыв -> bypass + следующий раз direct
		cacheBypass(sni)
		event := "DZEN_TLS_FAIL"
		if strings.Contains(err.Error(), "remote error: tls:") {
			event = "DZEN_TLS_REJECT"
		}
		flowLog(event + " host=" + sni + " err=" + err.Error())
		flowLog("DZEN_BYPASS_DIRECT sni=" + sni)
		return true, false
	}
	_ = tlsConn.SetDeadline(time.Now().Add(30 * time.Second))
	flowLog("DZEN_TLS_OK sni=" + sni)

	req, err := http.ReadRequest(bufio.NewReader(tlsConn))
	if err != nil {
		flowLog("DZEN_MITM_FAIL read-request:" + err.Error())
		return true, false
	}
	defer req.Body.Close()
	// Route only the selective host authenticated by the client SNI.
	upstreamHost := sni
	if req.Host != "" && !strings.EqualFold(req.Host, sni) && !strings.EqualFold(req.Host, net.JoinHostPort(sni, "443")) {
		flowLog("DZEN_MITM_FAIL host-mismatch")
		return true, false
	}
	ip, err := resolveRealIP(upstreamHost)
	if err != nil {
		flowLog("DZEN_MITM_FAIL resolve:" + err.Error())
		return true, false
	}
	up, err := dialTCP(net.JoinHostPort(ip, "443"))
	if err != nil {
		flowLog("DZEN_MITM_FAIL updial:" + err.Error())
		return true, false
	}
	defer up.Close()
	upTLS := tls.Client(up, &tls.Config{ServerName: upstreamHost, MinVersion: tls.VersionTLS12})
	_ = upTLS.SetDeadline(time.Now().Add(20 * time.Second))
	if err := upTLS.Handshake(); err != nil {
		flowLog("DZEN_MITM_FAIL uptls:" + err.Error())
		return true, false
	}
	_ = upTLS.SetDeadline(time.Now().Add(30 * time.Second))
	_ = tlsConn.SetDeadline(time.Now().Add(30 * time.Second))

	outReq := new(http.Request)
	*outReq = *req
	outReq.URL.Scheme = "https"
	outReq.URL.Host = upstreamHost
	outReq.RequestURI = ""
	outReq.Close = true
	outReq.Header = req.Header.Clone()
	outReq.Header.Del("Proxy-Connection")
	outReq.Header.Del("Accept-Encoding") // иначе br/gzip-тело не проинжектить
	if err := outReq.Write(upTLS); err != nil {
		flowLog("DZEN_MITM_FAIL reqwrite:" + err.Error())
		return true, false
	}
	resp, err := http.ReadResponse(bufio.NewReader(upTLS), outReq)
	if err != nil {
		flowLog("DZEN_MITM_FAIL upread:" + err.Error())
		return true, false
	}
	defer resp.Body.Close()
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if err := filterDzenResponse(resp); err != nil {
		flowLog("DZEN_MITM_FAIL body:" + err.Error())
		return true, false
	}
	if err := resp.Write(tlsConn); err != nil {
		flowLog("DZEN_MITM_FAIL respwrite:" + err.Error())
		return true, false
	}
	flowLog("DZEN_MITM_DONE host=" + sni + " ct=" + ct)
	return true, true
}

// Keep the body reader consistent with any rewritten content and length.
func filterDzenResponse(resp *http.Response) error {
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	resp.Close = true
	if strings.Contains(ct, "text/html") && (resp.Header.Get("Content-Encoding") == "" || resp.Header.Get("Content-Encoding") == "identity") {
		const limit = 16 * 1024 * 1024
		body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
		if err != nil {
			return err
		}
		if len(body) <= limit {
			body = []byte(dzenInjectCSS(string(body)))
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
			filtered, removed, ferr := dzenFilterJSON(body)
			if ferr != nil {
				flowLog("DZEN_JSON_SKIP parse-fail")
			} else if removed > 0 {
				final = filtered
				flowLog(fmt.Sprintf("DZEN_JSON_FILTERED removed=%d", removed))
			}
		case "gzip":
			raw, e1 := dzenGunzip(body)
			if e1 != nil {
				flowLog("DZEN_JSON_SKIP gunzip:" + e1.Error())
			} else {
				filtered, removed, ferr := dzenFilterJSON(raw)
				switch {
				case ferr != nil:
					flowLog("DZEN_JSON_SKIP parse-fail")
				case removed == 0:
				default:
					if out, e2 := dzenGzip(filtered); e2 != nil {
						flowLog("DZEN_JSON_SKIP regzip:" + e2.Error())
					} else {
						final = out
						flowLog(fmt.Sprintf("DZEN_JSON_FILTERED removed=%d", removed))
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
func dzenFilterJSON(body []byte) ([]byte, int, error) {
	var v interface{}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil, 0, err
	}
	removed, markers := dzenScrub(&v, "")
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

// dzenScrub рекурсивно обходит JSON: рекламные ЭЛЕМЕНТЫ массивов удаляет
// целиком (чтобы место схлопнулось), маркеры в ключах - только логирует.
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
			r, m := dzenScrub(&val, path+"."+k)
			t[k] = val
			removed += r
			markers = append(markers, m...)
		}
	case []interface{}:
		kept := t[:0]
		for i, el := range t {
			if m, ok := el.(map[string]interface{}); ok && dzenIsAdElement(m) {
				removed++
				flowLog(fmt.Sprintf("DZEN_JSON_AD_FOUND key=element path=%s[%d] type=feed-item id=%s",
					path, i, dzenElemID(m)))
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
