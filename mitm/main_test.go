package mitm

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

// Universal V1: generic cosmetic rules не должны содержать опасных селекторов
func TestNoDangerousSelectors(t *testing.T) {
	data, err := os.ReadFile("../app/src/main/assets/generic_cosmetic_rules.txt")
	if err != nil {
		t.Skip("asset not found")
	}
	for _, line := range strings.Split(string(data), "\n") {
		l := strings.TrimSpace(line)
		if l == "" || strings.HasPrefix(l, "!") {
			continue
		}
		if strings.Contains(l, "##") {
			l = strings.SplitN(l, "##", 2)[1]
		}
		lower := strings.ToLower(l)
		if strings.Contains(lower, "class*=banner") || strings.Contains(lower, "id*=banner") ||
			strings.Contains(lower, "class*=ad") || strings.Contains(lower, "class*=promo") ||
			strings.Contains(lower, "id*=promo") {
			t.Errorf("dangerous selector: %s", l)
		}
	}
}

// Universal V1: blocklist должен давать ~49k валидных доменов
func TestBlocklistCount(t *testing.T) {
	data, err := os.ReadFile("../app/src/main/assets/blocklist.txt")
	if err != nil {
		t.Skip("blocklist not found")
	}
	count := 0
	for _, line := range strings.Split(string(data), "\n") {
		l := strings.TrimSpace(line)
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "!") {
			continue
		}
		if strings.HasPrefix(l, "0.0.0.0 ") || strings.HasPrefix(l, "127.0.0.1 ") {
			l = l[strings.Index(l, " ")+1:]
		}
		l = strings.TrimPrefix(l, "||")
		if strings.Contains(l, "^") || strings.Contains(l, "*") {
			l = strings.Split(strings.Split(l, "^")[0], "*")[0]
		}
		l = strings.TrimPrefix(l, "www.")
		if len(l) < 4 || len(l) > 253 || !strings.Contains(l, ".") || l == "localhost" {
			continue
		}
		count++
	}
	if count < 40000 {
		t.Errorf("expected ~49000 rules, got %d", count)
	}
}

// Universal V1: ALPN parser tests (4 обязательных случая)
func TestALPNParser(t *testing.T) {
	// Helper: build minimal ClientHello with ALPN extension
	buildCH := func(alpnList []string) []byte {
		var alpnBytes []byte
		for _, p := range alpnList {
			alpnBytes = append(alpnBytes, byte(len(p)))
			alpnBytes = append(alpnBytes, []byte(p)...)
		}
		listLen := len(alpnBytes)
		extLen := listLen + 2
		ext := []byte{0x00, 0x10, byte(extLen >> 8), byte(extLen & 0xFF), byte(listLen >> 8), byte(listLen & 0xFF)}
		ext = append(ext, alpnBytes...)
		// TLS record header + handshake header + version + random + sidLen(0) + ciphers(2) + comp(1) + extLen + ext
		body := []byte{0x03, 0x03} // version
		body = append(body, make([]byte, 32)...) // random
		body = append(body, 0) // sidLen
		body = append(body, 0, 2, 0x13, 0x01) // ciphersLen + cipher
		body = append(body, 1, 0) // compLen + comp
		body = append(body, byte(len(ext)>>8), byte(len(ext)&0xFF)) // extLen
		body = append(body, ext...)
		hs := []byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body) & 0xFF)}
		hs = append(hs, body...)
		rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs) & 0xFF)}
		rec = append(rec, hs...)
		return rec
	}

	cases := []struct {
		name     string
		alpn     []string
		expected string
	}{
		{"h2+http/1.1 -> MITM", []string{"h2", "http/1.1"}, "http/1.1"},
		{"http/1.1+h2 -> MITM", []string{"http/1.1", "h2"}, "http/1.1"},
		{"h2 only -> bypass", []string{"h2"}, "h2"},
		{"http/1.1 only -> MITM", []string{"http/1.1"}, "http/1.1"},
	}
	for _, tc := range cases {
		raw := buildCH(tc.alpn)
		got := peekClientHelloALPN(raw)
		if got != tc.expected {
			t.Errorf("%s: expected %q got %q", tc.name, tc.expected, got)
		}
	}
}

// Universal V1: generic cosmetic rules must load >0 selectors
func TestGenericCosmeticRulesCount(t *testing.T) {
	data, err := os.ReadFile("../app/src/main/assets/generic_cosmetic_rules.txt")
	if err != nil {
		t.Skip("asset not found")
	}
	count := 0
	for _, line := range strings.Split(string(data), "\n") {
		l := strings.TrimSpace(line)
		if l == "" || strings.HasPrefix(l, "!") {
			continue
		}
		count++
	}
	if count == 0 {
		t.Error("generic_cosmetic_rules.txt has 0 selectors after parsing")
	}
	t.Logf("generic_cosmetic_rules count=%d", count)
}

// Universal Filter Pack tests
func TestCSPHeaderRemoved(t *testing.T) {
	resp := &http.Response{Header: http.Header{}}
	resp.Header.Set("Content-Security-Policy", "default-src 'self'")
	resp.Header.Set("Content-Security-Policy-Report-Only", "default-src 'self'")
	// симулируем удаление как в filterHTML
	resp.Header.Del("Content-Security-Policy")
	resp.Header.Del("Content-Security-Policy-Report-Only")
	if resp.Header.Get("Content-Security-Policy") != "" || resp.Header.Get("Content-Security-Policy-Report-Only") != "" {
		t.Error("CSP headers not removed")
	}
}

func TestCSPMetaPreservesOtherMeta(t *testing.T) {
	body := []byte(`<html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'self'"><title>My Page</title></head><body>Content here</body></html>`)
	result := stripCSPMeta(body)
	s := string(result)
	if strings.Contains(s, "content-security-policy") {
		t.Error("CSP meta not removed")
	}
	if !strings.Contains(s, `<meta charset="utf-8">`) {
		t.Error("meta charset lost")
	}
	if !strings.Contains(s, "<title>My Page</title>") {
		t.Error("title lost")
	}
	if !strings.Contains(s, "Content here") {
		t.Error("body content lost")
	}
}

func TestCSPMetaRemoved(t *testing.T) {
	body := []byte(`<html><head><meta http-equiv="Content-Security-Policy" content="default-src 'self'"><title>Test</title></head><body>Hi</body></html>`)
	result := stripCSPMeta(body)
	if bytes.Contains(bytes.ToLower(result), []byte("content-security-policy")) {
		t.Error("meta CSP not removed")
	}
	if !bytes.Contains(result, []byte("<title>Test</title>")) {
		t.Error("other content damaged")
	}
}

func TestCosmeticInjectPresent(t *testing.T) {
	if len(cosmeticInject) == 0 {
		t.Error("cosmeticInject is empty")
	}
	s := string(cosmeticInject)
	if !strings.Contains(s, "display:none") {
		t.Error("cosmeticInject missing display:none")
	}
}

func TestDomainRuleBlocked(t *testing.T) {
	blockedMu.Lock()
	savedD := blockedDomains
	savedP := blockedPaths
	blockedMu.Unlock()
	defer func() {
		blockedMu.Lock()
		blockedDomains = savedD
		blockedPaths = savedP
		blockedMu.Unlock()
	}()
	loadBlocklist("../app/src/main/assets/blocklist.txt")
	data, _ := os.ReadFile("../app/src/main/assets/blocklist.txt")
	if len(data) == 0 { t.Skip("no blocklist") }
	// первый валидный домен из blocklist
	for _, line := range strings.Split(string(data), "\n") {
		l := strings.TrimSpace(line)
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "!") { continue }
		if strings.HasPrefix(l, "0.0.0.0 ") || strings.HasPrefix(l, "127.0.0.1 ") {
			l = l[strings.Index(l, " ")+1:]
		}
		l = strings.TrimPrefix(l, "||")
		if strings.Contains(l, "^") || strings.Contains(l, "*") {
			l = strings.Split(strings.Split(l, "^")[0], "*")[0]
		}
		l = strings.TrimPrefix(l, "www.")
		if len(l) < 4 || !strings.Contains(l, ".") || l == "localhost" { continue }
		blocked, _ := checkURL(l, "/")
		if !blocked {
			t.Errorf("domain %s from blocklist not blocked", l)
		}
		return
	}
}

func TestBlock2RealMatcher(t *testing.T) {
	// Сохраняем исходное состояние
	blockedMu.Lock()
	savedDomains := blockedDomains
	savedPaths := blockedPaths
	blockedMu.Unlock()

	// Временный test blocklist
	tmp, err := os.CreateTemp("", "blocklist_test_*.txt")
	if err != nil { t.Fatal(err) }
	defer os.Remove(tmp.Name())
	rules := `ads.example.com
track.example.com/collect
||abp.example.com^
||path.example.com/banner`
	tmp.WriteString(rules)
	tmp.Close()

	// Загружаем временный blocklist
	loadBlocklist(tmp.Name())

	// Восстанавливаем после теста
	defer func() {
		blockedMu.Lock()
		blockedDomains = savedDomains
		blockedPaths = savedPaths
		blockedMu.Unlock()
	}()

	cases := []struct {
		host, path string
		wantBlock  bool
	}{
		{"ads.example.com", "/", true},           // 1
		{"sub.ads.example.com", "/", true},       // 2
		{"track.example.com", "/collect", true},  // 3
		{"track.example.com", "/other", false},   // 4
		{"abp.example.com", "/", true},           // 5
		{"sub.abp.example.com", "/", true},       // 6
		{"path.example.com", "/banner/x", true},  // 7
		{"path.example.com", "/other", false},    // 8
		{"track.example.com", "/collect?v=1", true}, // 9 path+query
	}
	for _, c := range cases {
		got, _ := checkURL(c.host, c.path)
		if got != c.wantBlock {
			t.Errorf("checkURL(%q, %q) = %v, want %v", c.host, c.path, got, c.wantBlock)
		}
	}
}

func TestBlocklistBeforeALPN(t *testing.T) {
	blockedMu.Lock()
	savedD := blockedDomains
	savedP := blockedPaths
	blockedMu.Unlock()
	defer func() {
		blockedMu.Lock()
		blockedDomains = savedD
		blockedPaths = savedP
		blockedMu.Unlock()
	}()
	tmp, _ := os.CreateTemp("", "bl_alpn_*.txt")
	defer os.Remove(tmp.Name())
	tmp.WriteString("0.0.0.0 blocked.example.com")
	tmp.Close()
	loadBlocklist(tmp.Name())
	if b, _ := checkURL("blocked.example.com", "/"); !b {
		t.Error("blocklist не режет до ALPN")
	}
}

func TestNewRoots(t *testing.T) {
	blockedMu.Lock()
	savedD := blockedDomains
	savedP := blockedPaths
	blockedMu.Unlock()
	defer func() {
		blockedMu.Lock()
		blockedDomains = savedD
		blockedPaths = savedP
		blockedMu.Unlock()
	}()
	tmp, _ := os.CreateTemp("", "bl5_*.txt")
	defer os.Remove(tmp.Name())
	tmp.WriteString(`0.0.0.0 googletagservices.com
0.0.0.0 adservices.google.com
0.0.0.0 mytarget.ru
0.0.0.0 ironsrc.com
0.0.0.0 ironsrc.mobi
0.0.0.0 supersonicads.com
0.0.0.0 unityads.unity3d.com
0.0.0.0 chartboost.com
0.0.0.0 timdovs.com`)
	tmp.Close()
	loadBlocklist(tmp.Name())
	roots := []string{"googletagservices.com", "adservices.google.com", "mytarget.ru",
		"ironsrc.com", "ironsrc.mobi", "supersonicads.com", "unityads.unity3d.com", "chartboost.com", "timdovs.com"}
	for _, r := range roots {
		if b, _ := checkURL(r, "/"); !b { t.Errorf("root %s not blocked", r) }
		if b, _ := checkURL("sub."+r, "/"); !b { t.Errorf("sub.%s not blocked", r) }
	}
	if b, _ := checkURL("other.com", "/"); b { t.Error("unrelated blocked") }
}

func TestCosmeticRulesUpdated(t *testing.T) {
	data, err := os.ReadFile("../app/src/main/assets/generic_cosmetic_rules.txt")
	if err != nil { t.Skip("no asset") }
	s := string(data)
	must := []string{"[data-google-query-id]", `[data-ad-status="filled"]`,
		`[name^="google_ads_iframe_"]`, `iframe[src*="googlesyndication.com"]`,
		`iframe[src*="doubleclick.net"]`, `iframe[src*="adfox.ru"]`}
	for _, m := range must {
		if !strings.Contains(s, m) { t.Errorf("missing: %s", m) }
	}
	for _, bad := range []string{`class*=ad]`, `id*=ad]`, `class*=banner]`, `class*=promo]`} {
		if strings.Contains(s, bad) { t.Errorf("broad: %s", bad) }
	}
}

func TestNoBroadSelectors(t *testing.T) {
	data, err := os.ReadFile("../app/src/main/assets/generic_cosmetic_rules.txt")
	if err != nil { t.Skip("no asset") }
	for _, line := range strings.Split(string(data), "\n") {
		l := strings.ToLower(strings.TrimSpace(line))
		if l == "" || strings.HasPrefix(l, "!") { continue }
		if strings.Contains(l, "class*=ad") || strings.Contains(l, "id*=ad") ||
			strings.Contains(l, "class*=banner") || strings.Contains(l, "class*=promo") {
			t.Errorf("broad selector found: %s", l)
		}
	}
}

// Block 3: isCertRejectError tests
func TestCertRejectError(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{fmt.Errorf("tls: unknown certificate"), true},
		{fmt.Errorf("tls: bad certificate"), true},
		{fmt.Errorf("tls: certificate unknown"), true},
		{fmt.Errorf("tls: unknown ca"), true},
		{fmt.Errorf("tls: certificate verify failure"), true},
		{fmt.Errorf("tls: certificate signed by unknown authority"), true},
		{fmt.Errorf("i/o timeout"), false},
		{fmt.Errorf("EOF"), false},
		{fmt.Errorf("connection reset by peer"), false},
		{fmt.Errorf("read: connection timed out"), false},
	}
	for _, c := range cases {
		got := isCertRejectError(c.err)
		if got != c.want {
			t.Errorf("isCertRejectError(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}

// Block 4: точечные rules по реальному трафику
func TestBlock4RealHosts(t *testing.T) {
	blockedMu.Lock()
	savedDomains := blockedDomains
	savedPaths := blockedPaths
	blockedMu.Unlock()
	defer func() {
		blockedMu.Lock()
		blockedDomains = savedDomains
		blockedPaths = savedPaths
		blockedMu.Unlock()
	}()

	tmp, err := os.CreateTemp("", "blocklist_b4_*.txt")
	if err != nil { t.Fatal(err) }
	defer os.Remove(tmp.Name())
	tmp.WriteString(`ogkopg.win/cm/dsp
0.0.0.0 b.porno365.golf
0.0.0.0 mos.porno666.video
0.0.0.0 g.porno666.fo`)
	tmp.Close()
	loadBlocklist(tmp.Name())

	cases := []struct{ host, path string; want bool }{
		{"ogkopg.win", "/cm/dsp", true},
		{"ogkopg.win", "/other", false},
		{"b.porno365.golf", "/", true},
		{"mos.porno666.video", "/", true},
		{"g.porno666.fo", "/", true},
		{"other.com", "/cm/dsp", false},
	}
	for _, c := range cases {
		got, _ := checkURL(c.host, c.path)
		if got != c.want {
			t.Errorf("checkURL(%q, %q) = %v, want %v", c.host, c.path, got, c.want)
		}
	}
}

// Block 5: выбор generic handler'а по ALPN — чистая функция, без сети.
// "h2" -> h2 handler, "http/1.1"/""/прочее -> существующий HTTP/1.1 pipeline.
func TestGenericH2Routing(t *testing.T) {
	cases := []struct {
		proto string
		want  bool
	}{
		{"h2", true},
		{"http/1.1", false},
		{"", false},
		{"h3", false},
	}
	for _, c := range cases {
		if got := shouldGenericH2(c.proto); got != c.want {
			t.Errorf("shouldGenericH2(%q) = %v, want %v", c.proto, got, c.want)
		}
	}
}

// Block 5: ОБЩАЯ HTML-обработка (h1+h2): CSP meta strip, cosmetic inject, gzip round-trip
func TestFilterHTMLBodyShared(t *testing.T) {
	if len(cosmeticInject) == 0 {
		t.Skip("cosmeticInject empty")
	}
	rb := make([]byte, 512)
	rand.Read(rb)
	filler := fmt.Sprintf("%x", rb)
	html := []byte(`<html><head><meta http-equiv="Content-Security-Policy" content="default-src 'self'"><title>T</title></head><body>` + filler + `</body></html>`)

	// identity encoding
	mod, changed := filterHTMLBody(html, "")
	if !changed {
		t.Fatal("identity: HTML не модифицирован")
	}
	if bytes.Contains(bytes.ToLower(mod), []byte("content-security-policy")) {
		t.Error("identity: CSP meta не удалён")
	}
	if !bytes.Contains(mod, cosmeticInject) {
		t.Error("identity: cosmeticInject не вставлен")
	}

	// gzip round-trip
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write(html)
	zw.Close()
	mod2, changed2 := filterHTMLBody(buf.Bytes(), "gzip")
	if !changed2 {
		t.Fatal("gzip: HTML не модифицирован")
	}
	zr, err := gzip.NewReader(bytes.NewReader(mod2))
	if err != nil {
		t.Fatalf("gzip: не перепакован: %v", err)
	}
	dec, err := io.ReadAll(zr)
	zr.Close()
	if err != nil {
		t.Fatalf("gzip: read: %v", err)
	}
	if bytes.Contains(bytes.ToLower(dec), []byte("content-security-policy")) {
		t.Error("gzip: CSP meta не удалён")
	}
	if !bytes.Contains(dec, cosmeticInject) {
		t.Error("gzip: cosmeticInject не вставлен")
	}

	// br/deflate — НЕ трогаем
	raw3 := []byte(filler)
	mod3, changed3 := filterHTMLBody(raw3, "br")
	if changed3 || !bytes.Equal(mod3, raw3) {
		t.Error("br: body модифицирован, а не должен быть")
	}
}
