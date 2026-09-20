package mitm

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// loadOrCreateCA загружает CA из dir, а если его там нет — генерирует
// и сохраняет один раз. Сертификат живёт между перезапусками: пользователь
// устанавливает его в систему один раз, и доверие не слетает.
// Возвращает ключевую пару и PEM сертификата (нужен экрану установки).
//
// Ключ — ECDSA P-256, а не RSA: goproxy подписывает сертификат на КАЖДОЕ
// новое HTTPS-соединение, и RSA-2048 (~50-100 мс на подпись) под полным
// туннелем уводил CPU в пик и замораживал интерфейс. ECDSA подписывает
// за доли миллисекунды.
var caFileMu sync.Mutex
var caInitMu sync.Mutex

func loadOrCreateCA(dir string) (tls.Certificate, []byte, error) {
	caFileMu.Lock()
	defer caFileMu.Unlock()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	if certErr == nil && keyErr == nil {
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		return cert, certPEM, err
	}
	// Never silently replace a CA already installed by the user.
	if !os.IsNotExist(certErr) || !os.IsNotExist(keyErr) {
		return tls.Certificate{}, nil, fmt.Errorf("cannot load existing CA: cert=%v key=%v", certErr, keyErr)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Config AdBlock CA", Organization: []string{"Config"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		return tls.Certificate{}, nil, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return tls.Certificate{}, nil, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	return cert, certPEM, err
}

// InitMitmCA prepares the existing signing CA without starting any proxy.
func InitMitmCA(filesDir string) (err error) {
	caInitMu.Lock()
	defer caInitMu.Unlock()
	defer func() {
		if err != nil {
			flowLog("HEV_CA_INIT_FAIL " + err.Error())
		} else {
			flowLog("HEV_CA_INIT_OK")
		}
	}()
	cert, _, err := loadOrCreateCA(filesDir)
	if err != nil {
		return err
	}
	if len(cert.Certificate) == 0 {
		return fmt.Errorf("CA certificate is empty")
	}
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return err
	}
	if !parsed.IsCA || parsed.KeyUsage&x509.KeyUsageCertSign == 0 {
		return fmt.Errorf("certificate cannot sign CA leaves")
	}
	if now := time.Now(); now.Before(parsed.NotBefore) || now.After(parsed.NotAfter) {
		return fmt.Errorf("CA is outside its validity period")
	}
	mitmCAMu.Lock()
	same := mitmCACert != nil && mitmCAX509 != nil && bytes.Equal(mitmCAX509.Raw, parsed.Raw)
	mitmCAMu.Unlock()
	if !same {
		setMITMCA(cert, parsed)
	}
	_, err = certForName("dzen.ru")
	return err
}

// ActiveCAFingerprint identifies the signer actually loaded in this process.
func ActiveCAFingerprint() string {
	mitmCAMu.Lock()
	defer mitmCAMu.Unlock()
	if mitmCAX509 == nil {
		return ""
	}
	return fmt.Sprintf("%X", sha256.Sum256(mitmCAX509.Raw))
}
