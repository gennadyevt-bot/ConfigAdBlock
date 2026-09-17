// MITM engine for Config AdBlock.
// Local forward proxy on 127.0.0.1:8080 decrypts TLS with a per-install CA.
// Blocklist (domains) + cosmetic (CSS/JS) filtering in OnRequest/OnResponse.
package mitm

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log"
	"sync/atomic"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/elazarl/goproxy"
)

// DoHHosts — DoH/DoT-эндпоинты: их НЕЛЬЗЯ MITM'ить (клиенты не доверяют
// нашему CA -> "unknown certificate" -> DNS мёртв). Пакетный уровень:
// используется и старым прокси (goproxy), и нашим пайплайном (tun.go).
var DoHHosts = map[string]bool{
	"1.1.1.1": true, "1.0.0.1": true, "8.8.8.8": true, "8.8.4.4": true,
	"9.9.9.9": true, "149.112.112.112": true,
	"77.88.8.8": true, "77.88.8.1": true,
	"94.140.14.14": true, "94.140.15.15": true,
	"dns.google": true, "mozilla.cloudflare-dns.com": true,
	"cloudflare-dns.com": true, "dns.adguard-dns.com": true,
	"common.dot.dns.yandex.net": true,
}

// dohHandler реализует goproxy.HttpsHandler для прямого туннелирования.
type dohHandler struct {
	action *goproxy.ConnectAction
}

func (h dohHandler) HandleConnect(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
	return h.action, host
}

const proxyBindAll = "127.0.0.1:0"

// mitmCfgFunc — фабрика tls.Config с GetCertificate нашего CA.
var mitmCfgFunc func(host string, ctx *goproxy.ProxyCtx) (*tls.Config, error)

// proxyCur — реальный адрес прокси (порт выбирается ОС на каждый старт:
// зомби-процесс на фиксированном 8080 больше не мешает).
// Читается ТОЛЬКО через atomic.Value: если кто-то случайно держит proxyMu,
// 443-потоки не должны умирать на чтении адреса (так гибли 101 поток).
var proxyCurAddrV atomic.Value

func proxyCurAddr() string {
	if v := proxyCurAddrV.Load(); v != nil {
		return v.(string)
	}
	return "127.0.0.1:0"
}

var (
	proxyMu        sync.Mutex
	proxySrv       *http.Server
	blockedDomains = make(map[string]bool)
	blockedMu      sync.RWMutex
)

// Ping — проверка, что gomobile-runtime жив и отвечает.
func Ping() int64 { return 42 }

// stage пишет метку стадии в файлы приложения (читает Kotlin и показывает
// в журнале — находим точное место зависания startProxy).
func stage(filesDir, s string) {
	_ = os.WriteFile(filepath.Join(filesDir, "stage.txt"), []byte(s), 0644)
}

// CaCertPem возвращает PEM сертификата ЦА — для экрана установки
// сертификата. CA при необходимости генерируется и сохраняется в filesDir.
func CaCertPem(filesDir string) ([]byte, error) {
	_, certPEM, err := loadOrCreateCA(filesDir)
	return certPEM, err
}

// loadBlocklist читает список доменов (hosts-формат "0.0.0.0 domain"
// или просто домен на строку; '#' — комментарий).
func loadBlocklist(path string) {
	f, err := os.Open(path)
	if err != nil {
		log.Printf("[MITM] blocklist not loaded: %v", err)
		return
	}
	defer f.Close()
	m := make(map[string]bool)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		d := strings.TrimSpace(strings.ToLower(sc.Text()))
		if d == "" || strings.HasPrefix(d, "#") {
			continue
		}
		if fields := strings.Fields(d); len(fields) == 2 {
			d = fields[1]
		}
		if fields := strings.Fields(d); len(fields) > 0 {
			d = fields[0]
		}
		if d == "0.0.0.0" || d == "127.0.0.1" || d == "::1" || d == "255.255.255.255" || d == "::" {
			continue
		}
		d = strings.TrimSuffix(d, ".")
		m[d] = true
	}
	blockedMu.Lock()
	blockedDomains = m
	blockedMu.Unlock()
	log.Printf("[MITM] blocklist: %d domains", len(m))
}

// isBlocked проверяет домен и его родителей (тот же алгоритм, что в
// Blocklist.kt приложения).
func isBlocked(host string) bool {
	d := strings.ToLower(strings.TrimSuffix(host, "."))
	if i := strings.LastIndex(d, ":"); i >= 0 {
		d = d[:i] // отрезаем порт
	}
	for d != "" {
		blockedMu.RLock()
		hit := blockedDomains[d]
		blockedMu.RUnlock()
		if hit {
			return true
		}
		idx := strings.Index(d, ".")
		if idx < 0 {
			break
		}
		d = d[idx+1:]
	}
	return false
}

// StartProxy запускает локальный MITM-прокси на 127.0.0.1:8080.
// filesDir — каталог файлов приложения (там хранится CA между запусками).
// blocklistPath — файл со списком доменов для блокировки.
func StartProxy(filesDir string, blocklistPath string) error {
	proxyMu.Lock()
	defer proxyMu.Unlock()
	if proxySrv != nil {
		return errors.New("proxy already running")
	}

	stage(filesDir, "A: enter startProxy")
	ca, _, err := loadOrCreateCA(filesDir)
	if err != nil {
		stage(filesDir, "A2: CA error "+err.Error())
		return err
	}
	stage(filesDir, "B: CA loaded")
	loadBlocklist(blocklistPath)
	stage(filesDir, "C: blocklist loaded")

	tlsCfg := goproxy.TLSConfigFromCA(&ca)
	// свой 443-пайплайн (tun.go) подписывает сертификаты сам —
	// отдаём ему CA и распарсенный сертификат для подписи.
	if len(ca.Certificate) > 0 {
		if xc, perr := x509.ParseCertificate(ca.Certificate[0]); perr == nil {
			setMITMCA(ca, xc)
		}
	}
	// КЛЮЧЕВОЕ: OkConnect — действие по умолчанию для ВСЕХ CONNECT-ов.
	// ConnectAccept = голый туннель без расшифровки (фильтр не видит
	// трафик — так было и реклама шла мимо). ConnectMitm = расшифровка
	// нашим CA — именно это и нужно для блокировки.
	goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: tlsCfg}
	goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: tlsCfg}
	goproxy.HTTPMitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectHTTPMitm, TLSConfig: tlsCfg}

	g := goproxy.NewProxyHttpServer()
	g.Verbose = false

	// DoH-серверы (DNS поверх HTTPS, к которым ломятся браузеры) НЕ
	// пропускаем через MITM: поддельный сертификат без IP-SAN рвёт TLS
	// для IP-литералов (1.1.1.1 и т.п.) -> DoH мёртв -> браузер не может
	// резолвить -> "не удаётся открыть веб-страницу". Туннелируем их
	// напрямую (настоящие сертификаты), фильтруем весь остальной трафик.
	dohHosts := DoHHosts
	dohAccept := &goproxy.ConnectAction{Action: goproxy.ConnectAccept}
	g.OnRequest(goproxy.ReqConditionFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) bool {
		return dohHosts[req.URL.Hostname()]
	})).HandleConnect(dohHandler{action: dohAccept})

	g.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		if isBlocked(req.Host) {
			// Пустой 403: баннер/скрипт не загрузится, страница не сломается
			return req, goproxy.NewResponse(req, "text/html", http.StatusForbidden, "")
		}
		return req, nil
	})
	g.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		return filterHTML(resp)
	})

	stage(filesDir, "D: before listen")
	ln, err := net.Listen("tcp", proxyBindAll)
	if err != nil {
		stage(filesDir, "D2: listen error "+err.Error())
		return err
	}
	stage(filesDir, "E: listening "+ln.Addr().String())
	// ВАЖНО: proxyMu УЖЕ захвачен на входе StartProxy (defer Unlock) —
	// повторный Lock() того же потока = вечный self-deadlock. Здесь
	// пишем без повторного захвата.
	proxyCurAddrV.Store(ln.Addr().String())
	proxySrv = &http.Server{Addr: ln.Addr().String(), Handler: g}
	go func() {
		if err := proxySrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("[MITM] proxy error: %v", err)
		}
	}()
	stage(filesDir, "F: serve started")
	log.Printf("[MITM] proxy on %s (MITM all)", proxyCurAddr())
	return nil
}

// StopProxy останавливает прокси (без убийства процесса).
func StopProxy() {
	proxyMu.Lock()
	defer proxyMu.Unlock()
	if proxySrv != nil {
		_ = proxySrv.Close()
		proxySrv = nil
	}
}
