// MITM engine for Config AdBlock.
// Local forward proxy on 127.0.0.1:8080 decrypts TLS with a per-install CA.
// Blocklist (domains) + cosmetic (CSS/JS) filtering in OnRequest/OnResponse.
package mitm

import (
	"bufio"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/elazarl/goproxy"
)

const proxyBindAll = "127.0.0.1:0"

// proxyCur — реальный адрес прокси (порт выбирается ОС на каждый старт:
// зомби-процесс на фиксированном 8080 больше не мешает).
var proxyCur string

func proxyCurAddr() string {
	proxyMu.Lock()
	defer proxyMu.Unlock()
	return proxyCur
}

var (
	proxyMu        sync.Mutex
	proxySrv       *http.Server
	blockedDomains = make(map[string]bool)
	blockedMu      sync.RWMutex
)

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

	ca, _, err := loadOrCreateCA(filesDir)
	if err != nil {
		return err
	}
	loadBlocklist(blocklistPath)

	tlsCfg := goproxy.TLSConfigFromCA(&ca)
	// КЛЮЧЕВОЕ: OkConnect — действие по умолчанию для ВСЕХ CONNECT-ов.
	// ConnectAccept = голый туннель без расшифровки (фильтр не видит
	// трафик — так было и реклама шла мимо). ConnectMitm = расшифровка
	// нашим CA — именно это и нужно для блокировки.
	goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: tlsCfg}
	goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: tlsCfg}
	goproxy.HTTPMitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectHTTPMitm, TLSConfig: tlsCfg}

	g := goproxy.NewProxyHttpServer()
	g.Verbose = false

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

	ln, err := net.Listen("tcp", proxyBindAll)
	if err != nil {
		return err
	}
	proxyMu.Lock()
	proxyCur = ln.Addr().String()
	proxyMu.Unlock()
	proxySrv = &http.Server{Addr: proxyCur, Handler: g}
	go func() {
		if err := proxySrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("[MITM] proxy error: %v", err)
		}
	}()
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
