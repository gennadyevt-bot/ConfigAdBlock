package mitm

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestHevCAInitAndTLS(t *testing.T) {
	dir := t.TempDir()
	if err := InitMitmCA(dir); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := InitMitmCA(dir); err != nil {
				t.Error(err)
			}
			if _, err := certForName("m.dzen.ru"); err != nil {
				t.Error(err)
			}
			CaInfo()
			LeafVerify()
		}()
	}
	wg.Wait()
	after, _ := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if !bytes.Equal(before, after) {
		t.Fatal("CA changed on reinit")
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(before)
	for _, trusted := range []bool{true, false} {
		ClearBypassCache()
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		client, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			listener.Close()
			t.Fatal(err)
		}
		server, err := listener.Accept()
		listener.Close()
		if err != nil {
			client.Close()
			t.Fatal(err)
		}
		server.SetDeadline(time.Now().Add(3 * time.Second))
		client.SetDeadline(time.Now().Add(3 * time.Second))
		done := make(chan struct{})
		go func() { defer close(done); handleDzenMITM(server, "dzen.ru", nil) }()
		pool := roots
		if !trusted {
			pool = x509.NewCertPool()
		}
		c := tls.Client(client, &tls.Config{ServerName: "dzen.ru", RootCAs: pool, NextProtos: []string{"http/1.1"}})
		err = c.Handshake()
		client.Close()
		<-done
		if trusted && err != nil {
			t.Fatal(err)
		}
		if !trusted && err == nil {
			t.Fatal("untrusted certificate accepted")
		}
		if trusted && !strings.Contains(FlowLog(), "DZEN_TLS_OK sni=dzen.ru") {
			t.Fatal(FlowLog())
		}
		if !trusted && !strings.Contains(FlowLog(), "DZEN_TLS_REJECT host=dzen.ru") {
			t.Fatal(FlowLog())
		}
	}
	ClearBypassCache()
}
func TestDzenNoCAFailsOpen(t *testing.T) {
	ClearBypassCache()
	caGenerationMu.Lock()
	mitmCAMu.Lock()
	mitmCACert = nil
	mitmCAX509 = nil
	mitmCAMu.Unlock()
	certCacheMu.Lock()
	certCache = map[string]*tls.Certificate{}
	certCacheMu.Unlock()
	caGenerationMu.Unlock()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	handled, _ := handleDzenMITM(a, "dzen.ru", nil)
	if handled || isBypassed("dzen.ru", "") {
		t.Fatal("missing CA consumed connection or cached bypass")
	}
	done := make(chan error, 1)
	go func() { _, err := b.Write([]byte{42}); done <- err }()
	a.SetDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1)
	if _, err := io.ReadFull(a, buf); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(FlowLog(), "DZEN_CA_FAIL host=dzen.ru") {
		t.Fatal(FlowLog())
	}
}
func TestInitCAFailurePreservesExistingCert(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ca.crt")
	original := []byte("existing incomplete CA")
	os.WriteFile(path, original, 0600)
	if err := InitMitmCA(dir); err == nil {
		t.Fatal("expected error")
	}
	got, _ := os.ReadFile(path)
	if !bytes.Equal(got, original) {
		t.Fatal("existing CA replaced")
	}
}

func TestDzenFilteredResponseBody(t *testing.T) {
	original := "<html><head></head><body>content</body></html>"
	resp := &http.Response{StatusCode: 200, ProtoMajor: 1, ProtoMinor: 1, Header: http.Header{"Content-Type": []string{"text/html"}}, Body: io.NopCloser(strings.NewReader(original)), ContentLength: int64(len(original))}
	if err := filterDzenResponse(resp); err != nil {
		t.Fatal(err)
	}
	var wire bytes.Buffer
	if err := resp.Write(&wire); err != nil {
		t.Fatal(err)
	}
	parsed, err := http.ReadResponse(bufio.NewReader(&wire), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(parsed.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "data-cablock") || !strings.Contains(string(body), "content") {
		t.Fatalf("missing rewritten body %s", body)
	}
	if parsed.ContentLength != int64(len(body)) {
		t.Fatal("incorrect length")
	}
}
