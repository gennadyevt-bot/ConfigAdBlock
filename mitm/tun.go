package mitm

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
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

	direct443 int64
)

// SetDirect443 — отладочный режим: 443-й порт тоже напрямую, без MITM.
// Контрольный эксперимент: отсекает весь слой goproxy/сертификатов.
func SetDirect443(v bool) {
	if v {
		atomic.StoreInt64(&direct443, 1)
	} else {
		atomic.StoreInt64(&direct443, 0)
	}
}

func direct443On() bool { return atomic.LoadInt64(&direct443) == 1 }

// Protector реализуется на стороне Android: VpnService.protect(fd).
// Явная защита сокетов движка, без полагания только на
// addDisallowedApplication.
type Protector interface {
	Protect(fd int64) bool
}

var (
	protectorMu sync.RWMutex
	protector   Protector
)

func SetProtector(p Protector) {
	protectorMu.Lock()
	protector = p
	protectorMu.Unlock()
}

func protectedControl() func(string, string, syscall.RawConn) error {
	protectorMu.RLock()
	p := protector
	protectorMu.RUnlock()
	if p == nil {
		return nil
	}
	return func(network, address string, c syscall.RawConn) error {
		var perr error
		_ = c.Control(func(fd uintptr) {
			if !p.Protect(int64(fd)) {
				perr = fmt.Errorf("protect(%s) denied", address)
			}
		})
		return perr
	}
}

func dialTCP(addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: 10 * time.Second, Control: protectedControl()}
	return d.Dial("tcp", addr)
}

func dialUDP(addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: 4 * time.Second, Control: protectedControl()}
	return d.Dial("udp", addr)
}

var selfTestStr string

func SelfTestResult() string { return selfTestStr }

// NetSelfTest проверяет, что реально доступно из контекста приложения
// (всё по IP-литералам, без DNS). Результат — строка на экран.
func NetSelfTest() {
	parts := []string{}
	// 1) UDP 53 -> Яндекс (реальный DNS-запрос ya.ru)
	if c, err := dialUDP("77.88.8.8:53"); err == nil {
		q := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 2, 'y', 'a', 0, 0, 0, 1, 0, 1}
		_ = c.SetDeadline(time.Now().Add(4 * time.Second))
		if _, err := c.Write(q); err == nil {
			if n, err := c.Read(make([]byte, 512)); err == nil && n >= 12 {
				parts = append(parts, "u53y=OK")
			} else {
				parts = append(parts, "u53y=нет")
			}
		} else {
			parts = append(parts, "u53y=ошибка")
		}
		c.Close()
	} else {
		parts = append(parts, "u53y=x")
	}
	// 2) TLS 853 -> Яндекс DoT
	if c, err := tlsDial("77.88.8.8:853", "common.dot.dns.yandex.net"); err == nil {
		parts = append(parts, "t853y=OK")
		c.Close()
	} else {
		parts = append(parts, "t853y=нет")
	}
	// 3) TLS 853 -> AdGuard
	if c, err := tlsDial("94.140.14.14:853", "dns.adguard-dns.com"); err == nil {
		parts = append(parts, "t853a=OK")
		c.Close()
	} else {
		parts = append(parts, "t853a=нет")
	}
	// 4) TLS 443 -> AdGuard DoH
	if c, err := tlsDial("94.140.14.14:443", "dns.adguard-dns.com"); err == nil {
		parts = append(parts, "t443a=OK")
		c.Close()
	} else {
		parts = append(parts, "t443a=нет")
	}
	// 5) TLS 443 -> dns.google (для сравнения)
	if c, err := tlsDial("8.8.8.8:853", "dns.google"); err == nil {
		parts = append(parts, "t853g=OK")
		c.Close()
	} else {
		parts = append(parts, "t853g=нет")
	}
	selfTestStr = strings.Join(parts, " ")
}

func tlsDial(addr, serverName string) (net.Conn, error) {
	d := net.Dialer{Timeout: 5 * time.Second, Control: protectedControl()}
	return tls.DialWithDialer(&d, "tcp", addr, &tls.Config{ServerName: serverName})
}

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

// StackStats возвращает счётчики пакетов стека: отвечает на вопрос GPT —
// видит ли gVisor вообще пакеты (вкл. IPv6), и доходят ли TCP/UDP до стека.
func StackStats() string {
	stackMu.Lock()
	st := stackInst
	stackMu.Unlock()
	if st == nil {
		return "stack: нет"
	}
	s := st.Stats()
	return "ip=" + strconv.FormatUint(s.IP.PacketsReceived.Value(), 10) +
		" tcpseg=" + strconv.FormatUint(s.TCP.ValidSegmentsReceived.Value(), 10) +
		" udp=" + strconv.FormatUint(s.UDP.PacketsReceived.Value(), 10)
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

// flowLog — кольцо последних TCP-потоков для экрана самотеста.
var (
	flowMu   sync.Mutex
	flowRing []string
)

func flowLog(s string) {
	flowMu.Lock()
	flowRing = append(flowRing, s)
	if len(flowRing) > 16 {
		flowRing = flowRing[len(flowRing)-16:]
	}
	flowMu.Unlock()
}

var (
	gpOk       int64
	gpFail     int64
	gpDial     int64
	t443seen   int64
	quicRelays int64
)

func T443Seen() int64   { return atomic.LoadInt64(&t443seen) }
func QuicRelays() int64 { return atomic.LoadInt64(&quicRelays) }

func GpOk() int64   { return atomic.LoadInt64(&gpOk) }
func GpFail() int64 { return atomic.LoadInt64(&gpFail) }
func GpDial() int64 { return atomic.LoadInt64(&gpDial) }

// FlowLog возвращает последние потоки одной строкой.
func FlowLog() string {
	flowMu.Lock()
	defer flowMu.Unlock()
	return strings.Join(flowRing, " | ")
}

func (t *tunHandler) HandleTCP(conn adapter.TCPConn) {
	defer conn.Close()
	atomic.AddInt64(&tcpTry, 1)
	id := conn.ID()
	host := id.LocalAddress.String()
	port := int(id.LocalPort)
	hp := net.JoinHostPort(host, strconv.Itoa(port))
	if port == 443 {
		atomic.AddInt64(&t443seen, 1)
	}

	// Не-TLS порты (и 443 в отладочном режиме) — напрямую, без MITM
	if port != 443 || direct443On() {
		up, err := dialTCP(hp)
		if err != nil {
			setErr(fmt.Errorf("direct %s: %w", hp, err))
			flowLog(hp + "→dirX")
			return
		}
		atomic.AddInt64(&directCnt, 1)
		flowLog(hp + "→dir")
		relay(conn, up)
		return
	}

	// 443 -> goproxy (CONNECT, там MITM и фильтры)
	g, err := dialTCP(proxyCurAddr())
	if err != nil {
		setErr(fmt.Errorf("dial goproxy %s: %w", proxyCurAddr(), err))
		atomic.AddInt64(&gpDial, 1)
		flowLog(hp + "→gpDialX")
		return
	}
	_, _ = fmt.Fprintf(g, "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n", host, port, host, port)
	br := bufio.NewReader(g)
	status, err := br.ReadString('\n')
	if err != nil || !strings.Contains(status, "200") {
		_ = g.Close()
		atomic.AddInt64(&gpFail, 1)
		setErr(fmt.Errorf("CONNECT %s -> %q", hp, strings.TrimSpace(status)))
		flowLog(hp + "→gpFAIL")
		return
	}
	atomic.AddInt64(&gpOk, 1)
	flowLog(hp + "→gp200")
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

// Простейший кэш DNS-ответов: резко снижает зависимость от живости DoT.
var (
	dnsCacheMu sync.Mutex
	dnsCache   = map[string][]byte{}
	dnsCacheN  int
)

func dnsCacheGet(key string) ([]byte, bool) {
	dnsCacheMu.Lock()
	defer dnsCacheMu.Unlock()
	v, ok := dnsCache[key]
	return v, ok
}

func dnsCachePut(key string, v []byte) {
	dnsCacheMu.Lock()
	defer dnsCacheMu.Unlock()
	if dnsCacheN > 2048 {
		dnsCache = map[string][]byte{}
		dnsCacheN = 0
	}
	cp := make([]byte, len(v))
	copy(cp, v)
	dnsCache[key] = cp
	dnsCacheN++
}

// Апстримы, доступные из РФ: AdGuard DNS (сам режет рекламу на DNS-уровне)
// и Яндекс. Cloudflare/Google с 2024 у большинства российских операторов
// заблокированы — оттуда и было "DoH: все апстримы недоступны".
var udpUpstreams = []string{"94.140.14.14:53", "77.88.8.8:53", "8.8.8.8:53"}

var dohEndpoints = []string{
	"https://94.140.14.14/dns-query",
	"https://dns.google/dns-query",
}

var dotEndpoints = []struct {
	addr string
	name string
}{
	{"94.140.14.14:853", "dns.adguard-dns.com"},
	{"77.88.8.8:853", "common.dot.dns.yandex.net"},
}

// resolveDoT: DNS-over-TLS (порт 853). Оператор режет plain UDP 53 —
// 853 проходит, это и есть рабочий путь.
func resolveDoT(query []byte) ([]byte, error) {
	var lastErr error
	for _, ep := range dotEndpoints {
		conn, err := tlsDial(ep.addr, ep.name)
		if err != nil {
			lastErr = fmt.Errorf("dot-%s dial: %w", ep.name, err)
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(6 * time.Second))
		var lb [2]byte
		binary.BigEndian.PutUint16(lb[:], uint16(len(query)))
		if _, err := conn.Write(lb[:]); err != nil {
			_ = conn.Close()
			lastErr = fmt.Errorf("dot-%s write: %w", ep.name, err)
			continue
		}
		if _, err := conn.Write(query); err != nil {
			_ = conn.Close()
			lastErr = fmt.Errorf("dot-%s write: %w", ep.name, err)
			continue
		}
		if _, err := io.ReadFull(conn, lb[:]); err != nil {
			_ = conn.Close()
			lastErr = fmt.Errorf("dot-%s read-hdr: %w", ep.name, err)
			continue
		}
		resp := make([]byte, binary.BigEndian.Uint16(lb[:]))
		if _, err := io.ReadFull(conn, resp); err != nil {
			_ = conn.Close()
			lastErr = fmt.Errorf("dot-%s read: %w", ep.name, err)
			continue
		}
		_ = conn.Close()
		if len(resp) >= 12 {
			return resp, nil
		}
		lastErr = fmt.Errorf("dot %s: короткий ответ", ep.addr)
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, errors.New("DoT: нет апстримов")
}

// resolveDNS: DoT (853) -> DoH (443) -> plain UDP (53, скорее всего мёртв).
func resolveDNS(query []byte) ([]byte, error) {
	if ans, err := resolveDoT(query); err == nil {
		return ans, nil
	} else {
		setErr(err)
	}
	if ans, err := resolveDoH(query); err == nil {
		return ans, nil
	} else {
		setErr(err)
	}
	var lastErr error
	for _, up := range udpUpstreams {
		rconn, err := dialUDP(up)
		if err != nil {
			lastErr = fmt.Errorf("dial %s: %w", up, err)
			continue
		}
		_ = rconn.SetDeadline(time.Now().Add(4*time.Second))
		if _, err := rconn.Write(query); err != nil {
			rconn.Close()
			lastErr = fmt.Errorf("write %s: %w", up, err)
			continue
		}
		rbuf := make([]byte, 4096)
		rn, err := rconn.Read(rbuf)
		rconn.Close()
		if err != nil || rn < 12 {
			lastErr = fmt.Errorf("read %s: %v", up, err)
			continue
		}
		atomic.AddInt64(&dnsGot, 1)
		return rbuf[:rn], nil
	}
	if lastErr != nil {
		setErr(lastErr)
	}
	return resolveDoH(query)
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
// UDP: релей в апстрим для ЛЮБОГО порта. Порт 53 — через DoT (оператор
// режет plain DNS). Остальное (QUIC/443 и др.) — напрямую, иначе браузеры
// зависают на QUIC без фолбэка и "интернета нет".
func (t *tunHandler) HandleUDP(conn adapter.UDPConn) {
	defer conn.Close()
	id := conn.ID()
	atomic.AddInt64(&udpTry, 1)
	isDNS := id.LocalPort == 53

	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 64*1024)
	n, err := conn.Read(buf)
	if err != nil || n <= 0 {
		return
	}

	if isDNS {
		key := string(buf[:n])
		if cached, ok := dnsCacheGet(key); ok {
			atomic.AddInt64(&udpCount, 1)
			_, _ = conn.Write(cached)
			return
		}
		ans, err := resolveDNS(buf[:n])
		if err != nil {
			setErr(err)
			return
		}
		dnsCachePut(key, ans)
		atomic.AddInt64(&udpCount, 1)
		_, _ = conn.Write(ans)
		return
	}

	// QUIC и прочий UDP: прямой релей в апстрим (dst из заголовка потока)
	dst := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))
	up, err := dialUDP(dst)
	if err != nil {
		return
	}
	defer up.Close()
	if _, err := up.Write(buf[:n]); err != nil {
		return
	}
	atomic.AddInt64(&quicRelays, 1)
	_ = up.SetReadDeadline(time.Now().Add(30 * time.Second))
	rbuf := make([]byte, 64*1024)
	for {
		rn, err := up.Read(rbuf)
		if err != nil || rn <= 0 {
			return
		}
		if _, err := conn.Write(rbuf[:rn]); err != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		_ = up.SetReadDeadline(time.Now().Add(30 * time.Second))
	}
}
