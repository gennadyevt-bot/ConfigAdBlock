// MITM engine for Config AdBlock.
// Listens on 127.0.0.1:8080 as forward proxy; decrypts TLS with a per-install CA.
// Filter logic (blocklist + cosmetic injection) is applied in OnRequest/OnResponse.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"math/big"
	"net/http"
	"time"

	"github.com/elazarl/goproxy"
)

// TODO(android side): generate/persist CA once, export cert PEM for user install.
func genCA() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Config AdBlock CA", Organization: []string{"Config"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

func main() {
	ca, err := genCA()
	if err != nil {
		log.Fatal("CA: ", err)
	}
	tlsCfg := goproxy.TLSConfigFromCA(&ca)
	goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectAccept, TLSConfig: tlsCfg}
	goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: tlsCfg}
	goproxy.HTTPMitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectHTTPMitm, TLSConfig: tlsCfg}

	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = false

	proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		// TODO 0.6.0: consult blocklist (domain), optionally block; disable QUIC hints.
		return req, nil
	})
	proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		// TODO 0.6.0: if text/html -> inject cosmetic CSS/JS to cut banner placeholders.
		return resp
	})

	log.Println("ConfigAdBlock MITM on 127.0.0.1:8080")
	log.Fatal(http.ListenAndServe("127.0.0.1:8080", proxy))
}
