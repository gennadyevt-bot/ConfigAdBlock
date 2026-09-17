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

// dialLocal — для 127.0.0.1: protect не нужен (loopback не идёт через
// VPN), а Java-колбэк protect() был кандидатом на вечный стопор
// 443-потоков после →gp-enter.
func dialLocal(addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: 10 * time.Second}
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
	handle443(conn, hp)
}

// handle443 вынесен отдельно, чтобы перехватить панику: gVisor молча
// глотает паники в обработчиках (72 потока исчезали бесследно).
// Счётчики этапов собственного MITM-пайплайна (матрица диагностики).
var (
	cliHello   int64
	cliTLSOk   int64
	cliTLSFail int64
	upDialOk   int64
	upDialFail int64
	upTLSOk    int64
	upTLSFail  int64
	httpReqN   int64
	httpRespN  int64
	blockedN   int64
)

func MitmStats() string {
	return "tls " + strconv.FormatInt(atomic.LoadInt64(&cliTLSOk), 10) + "/" + strconv.FormatInt(atomic.LoadInt64(&cliTLSFail), 10) +
		" up " + strconv.FormatInt(atomic.LoadInt64(&upDialOk), 10) + "/" + strconv.FormatInt(atomic.LoadInt64(&upDialFail), 10) +
		" utls " + strconv.FormatInt(atomic.LoadInt64(&upTLSOk), 10) + "/" + strconv.FormatInt(atomic.LoadInt64(&upTLSFail), 10) +
		" http " + strconv.FormatInt(atomic.LoadInt64(&httpReqN), 10) + "/" + strconv.FormatInt(atomic.LoadInt64(&httpRespN), 10) +
		" blk " + strconv.FormatInt(atomic.LoadInt64(&blockedN), 10)
}

// lookupA резолвит A-запись через наш DoT (не зависит от резолвера Go).
func lookupA(name string) (string, error) {
	q := []byte{0xAB, 0xCD, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, part := range strings.Split(name, ".") {
		if len(part) == 0 || len(part) > 63 {
			return "", errors.New("bad name")
		}
		q = append(q, byte(len(part)))
		q = append(q, part...)
	}
	q = append(q, 0, 0, 1, 0, 1)
	ans, err := resolveDNS(q)
	if err != nil {
		return "", err
	}
	if len(ans) < 12 {
		return "", errors.New("short answer")
	}
	qd := int(ans[4])<<8 | int(ans[5])
	an := int(ans[6])<<8 | int(ans[7])
	off := 12
	for i := 0; i < qd && off < len(ans); i++ {
		for off < len(ans) {
			l := int(ans[off])
			if l == 0 {
				off++
				break
			}
			if l&0xC0 == 0xC0 {
				off += 2
				break
			}
			off += 1 + l
		}
		off += 4
	}
	for i := 0; i < an && off+12 <= len(ans); i++ {
		for off < len(ans) {
			l := int(ans[off])
			if l == 0 {
				off++
				break
			}
			if l&0xC0 == 0xC0 {
				off += 2
				break
			}
			off += 1 + l
		}
		if off+10 > len(ans) {
			break
		}
		typ := int(ans[off])<<8 | int(ans[off+1])
		rdlen := int(ans[off+8])<<8 | int(ans[off+9])
		off += 10
		if typ == 1 && rdlen == 4 && off+4 <= len(ans) {
			return fmt.Sprintf("%d.%d.%d.%d", ans[off], ans[off+1], ans[off+2], ans[off+3]), nil
		}
		off += rdlen
	}
	return "", errors.New("no A record")
}

// handle443 — СОБСТВЕННЫЙ MITM-пайплайн (без goproxy): полная
// наблюдаемость всех этапов + блоклист + косметика.
func handle443(conn adapter.TCPConn, hp string) {
	defer func() {
		if r := recover(); r != nil {
			setErr(fmt.Errorf("PANIC 443 %s: %v", hp, r))
			flowLog(hp + "→PANIC")
		}
		_ = conn.Close()
	}()
	flowLog(hp + "→mitm")
	if mitmCfgFunc == nil {
		flowLog(hp + "→noCfg")
		return
	}
	hostOnly := hp
	if i := strings.LastIndex(hp, ":"); i > 0 {
		hostOnly = hp[:i]
	}
	cfg, cerr := mitmCfgFunc(hostOnly, nil)
	if cerr != nil || cfg == nil {
		setErr(fmt.Errorf("mitmCfg %s: %v", hp, cerr))
		flowLog(hp + "→cfgErr")
		return
	}
	tlsConn := tls.Server(conn, cfg)
	_ = tlsConn.SetDeadline(time.Now().Add(15 * time.Second))
	atomic.AddInt64(&cliHello, 1)
	if err := tlsConn.Handshake(); err != nil {
		atomic.AddInt64(&cliTLSFail, 1)
		setErr(fmt.Errorf("cliTLS %s: %w", hp, err))
		flowLog(hp + "→cliTLSfail")
		return
	}
	atomic.AddInt64(&cliTLSOk, 1)
	_ = tlsConn.SetDeadline(time.Time{})
	flowLog(hp + "→cliTLSok")
	br := bufio.NewReader(tlsConn)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		atomic.AddInt64(&httpReqN, 1)
		host := req.Host
		if host == "" {
			continue
		}
		if isBlocked(host) {
			atomic.AddInt64(&blockedN, 1)
			resp := &http.Response{StatusCode: 403, Status: "403 Forbidden", Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), ContentLength: 0, Close: true}
			resp.Header.Set("Content-Type", "text/html")
			_ = resp.Write(tlsConn)
			if req.Close {
				return
			}
			continue
		}
		atomic.AddInt64(&upDialOk, 0) // накрутка запрещена, держим структуру счётчиков
		target := host
		if !strings.Contains(target, ":") {
			target += ":443"
		}
		up, err := dialTCP(target)
		if err != nil {
			ip, lerr := lookupA(strings.Split(host, ":")[0])
			if lerr != nil {
				atomic.AddInt64(&upDialFail, 1)
				setErr(fmt.Errorf("upDial %s: %v / %v", target, err, lerr))
				write502(tlsConn)
				if req.Close {
					return
				}
				continue
			}
			up, err = dialTCP(net.JoinHostPort(ip, "443"))
			if err != nil {
				atomic.AddInt64(&upDialFail, 1)
				setErr(fmt.Errorf("upDial %s: %w", target, err))
				write502(tlsConn)
				if req.Close {
					return
				}
				continue
			}
		}
		atomic.AddInt64(&upDialOk, 1)
		serverName := strings.Split(host, ":")[0]
		upTLS := tls.Client(up, &tls.Config{ServerName: serverName})
		if err := upTLS.Handshake(); err != nil {
			atomic.AddInt64(&upTLSFail, 1)
			setErr(fmt.Errorf("upTLS %s: %w", serverName, err))
			_ = up.Close()
			write502(tlsConn)
			if req.Close {
				return
			}
			continue
		}
		atomic.AddInt64(&upTLSOk, 1)
		req.URL.Scheme = "https"
		req.URL.Host = target
		req.RequestURI = ""
		req.Header.Del("Proxy-Connection")
		req.Header.Del("Proxy-Authenticate")
		req.Header.Del("Proxy-Authorization")
		if err := req.Write(upTLS); err != nil {
			_ = up.Close()
			if req.Close {
				return
			}
			continue
		}
		resp, err := http.ReadResponse(bufio.NewReader(upTLS), req)
		if err != nil {
			_ = up.Close()
			setErr(fmt.Errorf("upRead %s: %w", serverName, err))
			write502(tlsConn)
			if req.Close {
				return
			}
			continue
		}
		atomic.AddInt64(&httpRespN, 1)
		resp = filterHTML(resp)
		if err := resp.Write(tlsConn); err != nil {
			_ = up.Close()
			return
		}
		_ = up.Close()
		if req.Close || resp.Close {
			return
		}
	}
}

func write502(w io.Writer) {
	_, _ = io.WriteString(w, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
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
