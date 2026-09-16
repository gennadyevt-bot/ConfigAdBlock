package mitm

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/xjasonlyu/tun2socks/v2/core"
	"github.com/xjasonlyu/tun2socks/v2/core/adapter"
	"github.com/xjasonlyu/tun2socks/v2/core/device"
	"github.com/xjasonlyu/tun2socks/v2/core/device/fdbased"
)

// Свой сетевой стек поверх Android TUN: TCP -> цепочка в goproxy (MITM),
// UDP 53 (DNS) -> прямой ретранслятор в 8.8.8.8. Engine-пакет не используем:
// его UDP-путь через прокси молча глушил DNS (интернет умирал целиком).
var (
	stackMu   sync.Mutex
	stackInst *stack.Stack
	stackDev  device.Device
)

// StartTunnel поднимает стек на fd (TUN из establish().detachFd()).
func StartTunnel(fd int64, mtu int64) error {
	dev, err := fdbased.Open(strconv.Itoa(int(fd)), uint32(mtu), 0)
	if err != nil {
		return err
	}
	st, err := core.CreateStack(&core.Config{
		LinkEndpoint:     dev,
		TransportHandler: &tunHandler{},
	})
	if err != nil {
		dev.Close()
		return err
	}
	stackMu.Lock()
	stackInst = st
	stackDev = dev
	stackMu.Unlock()
	return nil
}

// StopTunnel останавливает стек и закрывает fd (Android освободит TUN).
func StopTunnel() {
	stackMu.Lock()
	defer stackMu.Unlock()
	if stackInst != nil {
		stackInst.Close()
		stackInst = nil
	}
	if stackDev != nil {
		stackDev.Close()
		stackDev = nil
	}
}

type tunHandler struct{}

func (t *tunHandler) HandleTCP(conn adapter.TCPConn) {
	defer conn.Close()
	atomic.AddInt64(&tcpTry, 1)
	id := conn.ID()
	host := id.LocalAddress.String()
	port := int(id.LocalPort)

	// Не-TLS порты — напрямую, MITM там не нужен
	if port != 443 {
		up, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 10*time.Second)
		if err != nil {
			return
		}
		atomic.AddInt64(&directCnt, 1)
		relay(conn, up)
		return
	}

	// 443 -> goproxy (CONNECT, там MITM и фильтры)
	g, err := net.DialTimeout("tcp", proxyAddr, 10*time.Second)
	if err != nil {
		return
	}
	_, _ = fmt.Fprintf(g, "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n", host, port, host, port)
	br := bufio.NewReader(g)
	status, err := br.ReadString('\n')
	if err != nil || !strings.Contains(status, "200") {
		_ = g.Close()
		return
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			_ = g.Close()
			return
		}
		if line == "\r\n" {
			break
		}
	}
	atomic.AddInt64(&tcpCount, 1)
	if br.Buffered() > 0 {
		_, _ = io.CopyN(conn, br, int64(br.Buffered()))
	}
	relay(conn, g)
}

// DNS через DNS-over-HTTPS: операторы РФ перехватывают/глушет plain
// UDP 53, поэтому апстрим — только по 443 в обход перехвата.
var dohClient = &http.Client{Timeout: 6 * time.Second}

var dohEndpoints = []string{
	"https://1.1.1.1/dns-query",
	"https://1.0.0.1/dns-query",
	"https://dns.google/dns-query",
}

func resolveDoH(query []byte) ([]byte, error) {
	for _, url := range dohEndpoints {
		req, err := http.NewRequest("POST", url, bytes.NewReader(query))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/dns-message")
		req.Header.Set("Accept", "application/dns-message")
		resp, err := dohClient.Do(req)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if err != nil || resp.StatusCode != 200 || len(body) < 12 {
			continue
		}
		return body, nil
	}
	return nil, errors.New("DoH: все апстримы недоступны")
}

// DNS: каждый UDP-поток на порт 53 — один запрос-ответ.
func (t *tunHandler) HandleUDP(conn adapter.UDPConn) {
	defer conn.Close()
	id := conn.ID()
	atomic.AddInt64(&udpTry, 1)
	if id.LocalPort != 53 {
		return
	}
	_ = conn.SetReadDeadline(time.Now().Add(8 * time.Second))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n <= 0 {
		return
	}
	ans, err := resolveDoH(buf[:n])
	if err != nil {
		return
	}
	atomic.AddInt64(&udpCount, 1)
	_, _ = conn.Write(ans)
}
