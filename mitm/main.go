// MITM engine for Config AdBlock.
// Local forward proxy on 127.0.0.1:8080 decrypts TLS with a per-install CA.
// Filter logic (blocklist + cosmetic injection) is applied in OnRequest/OnResponse.
package mitm

import (
	"errors"
	"log"
	"net"
	"net/http"
	"sync"

	"github.com/elazarl/goproxy"
)

const proxyAddr = "127.0.0.1:8080"

var (
	proxyMu  sync.Mutex
	proxySrv *http.Server
)

// CaCertPem возвращает PEM сертификата ЦА — для экрана установки
// сертификата. CA при необходимости генерируется и сохраняется в filesDir.
func CaCertPem(filesDir string) ([]byte, error) {
	_, certPEM, err := loadOrCreateCA(filesDir)
	return certPEM, err
}

// StartProxy запускает локальный MITM-прокси на 127.0.0.1:8080.
// filesDir — каталог файлов приложения (там хранится CA между запусками).
func StartProxy(filesDir string) error {
	proxyMu.Lock()
	defer proxyMu.Unlock()
	if proxySrv != nil {
		return errors.New("proxy already running")
	}

	ca, _, err := loadOrCreateCA(filesDir)
	if err != nil {
		return err
	}

	tlsCfg := goproxy.TLSConfigFromCA(&ca)
	goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectAccept, TLSConfig: tlsCfg}
	goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: tlsCfg}
	goproxy.HTTPMitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectHTTPMitm, TLSConfig: tlsCfg}

	g := goproxy.NewProxyHttpServer()
	g.Verbose = false

	g.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		// TODO 0.6.0: consult blocklist (domain), optionally block; disable QUIC hints.
		return req, nil
	})
	g.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		// TODO 0.6.0: if text/html -> inject cosmetic CSS/JS to cut banner placeholders.
		return resp
	})

	ln, err := net.Listen("tcp", proxyAddr)
	if err != nil {
		return err
	}
	proxySrv = &http.Server{Addr: proxyAddr, Handler: g}
	go func() {
		if err := proxySrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("[MITM] proxy error: %v", err)
		}
	}()
	log.Printf("[MITM] proxy on %s", proxyAddr)
	return nil
}

// StopProxy останавливает прокси (без убийства процесса — в отличие от
// старого log.Fatal в Start()).
func StopProxy() {
	proxyMu.Lock()
	defer proxyMu.Unlock()
	if proxySrv != nil {
		_ = proxySrv.Close()
		proxySrv = nil
	}
}
