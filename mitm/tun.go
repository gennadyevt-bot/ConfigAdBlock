package mitm

import (
	"math/big"
	"encoding/pem"
	"crypto/x509/pkix"
	"crypto/x509"
	"crypto/rand"
	"crypto/elliptic"
	"crypto/ecdsa"
	"bufio"
	"crypto/sha256"
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
	if len(flowRing) > 80 {
		flowRing = flowRing[len(flowRing)-80:]
	}
	flowMu.Unlock()
}

var (
	gpOk       int64
	gpFail     int64
	gpDial     int64
	t443seen   int64
	quicRelays int64
	quicDrops  int64
	udpSeen    int64
)

// UdpSeen/QuicDrops — наблюдаемость UDP (диагностика GPT: весь UDP
// браузера логируется построчно, UDP/443 роняем для отката на TCP).
func UdpSeen() int64   { return atomic.LoadInt64(&udpSeen) }
func QuicDrops() int64 { return atomic.LoadInt64(&quicDrops) }

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
		atomic.AddInt64(&directCnt, 1)
		dfam := "v4"
		if strings.Contains(hp, ":") {
			dfam = "v6"
		}
		flowLog(fmt.Sprintf("tcp dst=%s fam=%s direct", hp, dfam))
		up, err := dialTCP(hp)
		if err != nil {
			setErr(fmt.Errorf("direct %s: %w", hp, err))
			flowLog(hp + "→dirX")
			return
		}
		relay(conn, up)
		return
	}

	// 443 -> goproxy (CONNECT, там MITM и фильтры)
	handle443(conn, hp)
}

// handle443 вынесен отдельно, чтобы перехватить панику: gVisor молча
// глотает паники в обработчиках (72 потока исчезали бесследно).
// Счётчики этапов собственного MITM-пайплайна (матрица диагностики).
// cliTLSFail — ТОЛЬКО реальные ошибки (alert/таймаут/обрыв до байт).
// cliTLSRace — бенigner обрыв: клиент прислал >=1 байт и корректно закрыл
// соединение посреди рукопожатия (Chrome гоняет параллельные коннекты
// и закрывает проигравшие). EOF после успешной передачи данных — normalEOF.
var (
	cliHello   int64
	dohPassN   int64
	cliTLSOk   int64
	cliTLSFail int64
	cliTLSRace int64
	acceptedN  int64
	upDialOk   int64
	upDialFail int64
	upTLSOk    int64
	upTLSFail  int64
	httpReqN   int64
	httpRespN  int64
	allowN     int64
	blockedN   int64
	c2uBytes   int64
	u2cBytes   int64
	normalEOF  int64
)

// isYandexAdHost — домены рекламной СИСТЕМЫ (Adfox / Yandex Ad Exchange),
// а не рекламодателей. По документации Adfox рекламная загрузка идёт
// через них; блокируем их, а не сайты типа rsvx.ru/myrecruit.ru.
func isYandexAdHost(host string) bool {
	h := strings.ToLower(host)
	if i := strings.LastIndex(h, ":"); i >= 0 {
		h = h[:i] // отрезаем порт
	}
	return h == "adfox.ru" || strings.HasSuffix(h, ".adfox.ru") ||
		h == "yandexadexchange.net" || strings.HasSuffix(h, ".yandexadexchange.net")
}

// adSuspicion возвращает причину подозрения на рекламу (или "").
// НИЧЕГО не блокирует — только помечает запрос в журнале строкой ADS?.
func adSuspicion(host, path string) string {
	h := strings.ToLower(host)
	p := strings.ToLower(path)
	switch {
	case strings.Contains(h, "adfox"):
		return "adfox"
	case strings.Contains(h, "an.yandex"):
		return "yandex-direct"
	case strings.Contains(h, "doubleclick") || strings.Contains(h, "googlesyndication"):
		return "google-ads"
	case strings.Contains(h, "lentainform"):
		return "lenta-adserver"
	case strings.Contains(h, "inverga"):
		return "inverga-ad"
	case strings.Contains(h, "yandexadexchange"):
		return "yandex-ad-exchange"
	case strings.Contains(p, "click"):
		return "click-path"
	case strings.HasPrefix(p, "/clck/"):
		return "yandex-click-tracker"
	case strings.HasPrefix(p, "/ads/") || strings.HasPrefix(p, "/showclicks/"):
		return "yandex-ads-path"
	case strings.Contains(p, "banner") || strings.Contains(p, "ads."):
		return "ad-path-keyword"
	}
	return ""
}

func MitmStats() string {
	return "acc " + strconv.FormatInt(atomic.LoadInt64(&acceptedN), 10) +
		" tls " + strconv.FormatInt(atomic.LoadInt64(&cliTLSOk), 10) + "/" + strconv.FormatInt(atomic.LoadInt64(&cliTLSFail), 10) +
		" race " + strconv.FormatInt(atomic.LoadInt64(&cliTLSRace), 10) +
		" up " + strconv.FormatInt(atomic.LoadInt64(&upDialOk), 10) + "/" + strconv.FormatInt(atomic.LoadInt64(&upDialFail), 10) +
		" utls " + strconv.FormatInt(atomic.LoadInt64(&upTLSOk), 10) + "/" + strconv.FormatInt(atomic.LoadInt64(&upTLSFail), 10) +
		" http " + strconv.FormatInt(atomic.LoadInt64(&httpReqN), 10) + "/" + strconv.FormatInt(atomic.LoadInt64(&httpRespN), 10) +
		" allow " + strconv.FormatInt(atomic.LoadInt64(&allowN), 10) +
		" blk " + strconv.FormatInt(atomic.LoadInt64(&blockedN), 10) +
		" c2u " + strconv.FormatInt(atomic.LoadInt64(&c2uBytes), 10) +
		" u2c " + strconv.FormatInt(atomic.LoadInt64(&u2cBytes), 10) +
		" eofOK " + strconv.FormatInt(atomic.LoadInt64(&normalEOF), 10)
}

// Своя фабрика сертификатов хостов (вместо goproxy TLSConfigFromCA —
// та паниковала на nil ctx). Подписываем нашим CA, кэшируем по имени,
// для IP-литералов кладём IP в SAN.
// caInfoStr / leafVerifyStr — вывод на экран для сверки отпечатков (GPT).
var (
	caInfoStr   string
	leafVerifyStr string
)

func CaInfo() string   { return caInfoStr }
func LeafVerify() string { return leafVerifyStr }

// verifyLeafSelfTest: генерируем тестовый leaf и проверяем цепочку
// до нашего CA так, как это делал бы клиент (issuer, SAN, срок, подпись).
func verifyLeafSelfTest() {
	mitmCAMu.Lock()
	caX := mitmCAX509
	mitmCAMu.Unlock()
	if caX == nil {
		leafVerifyStr = "leaf: нет CA"
		return
	}
	leaf, err := certForName("selftest.local")
	if err != nil {
		leafVerifyStr = "leaf: генерация FAIL: " + err.Error()
		return
	}
	lc, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		leafVerifyStr = "leaf: парсинг FAIL"
		return
	}
	roots := x509.NewCertPool()
	roots.AddCert(caX)
	opts := x509.VerifyOptions{
		DNSName:   "selftest.local",
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if _, err := lc.Verify(opts); err != nil {
		leafVerifyStr = "leaf: ПРОВЕРКА FAIL: " + err.Error()
		return
	}
	leafVerifyStr = "leaf: OK"
}

var (
	mitmCAMu   sync.Mutex
	mitmCACert *tls.Certificate
	mitmCAX509 *x509.Certificate
	certCacheMu sync.Mutex
	certCache   = map[string]*tls.Certificate{}
)

func setMITMCA(cert tls.Certificate, x509cert *x509.Certificate) {
	mitmCAMu.Lock()
	mitmCACert = &cert
	mitmCAX509 = x509cert
	mitmCAMu.Unlock()
	certCacheMu.Lock()
	certCache = map[string]*tls.Certificate{}
	certCacheMu.Unlock()
	// инфо на экран: subject + sha256 + срок — для сверки с установленным
	// в системе сертификатом (исключаем рассинхрон CA №1 vs CA №2)
	fp := sha256.Sum256(x509cert.Raw)
	caInfoStr = "CA: " + x509cert.Subject.CommonName +
		" sha256:" + fmt.Sprintf("%X", fp)[:16] +
		" до:" + x509cert.NotAfter.Format("2006-01-02")
	verifyLeafSelfTest()
}

func certForName(name string) (*tls.Certificate, error) {
	certCacheMu.Lock()
	if c, ok := certCache[name]; ok {
		certCacheMu.Unlock()
		return c, nil
	}
	certCacheMu.Unlock()

	mitmCAMu.Lock()
	ca := mitmCACert
	caX := mitmCAX509
	mitmCAMu.Unlock()
	if ca == nil || caX == nil {
		return nil, errors.New("no CA")
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(2, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(name); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{name}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caX, &key.PublicKey, ca.PrivateKey)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	certCacheMu.Lock()
	certCache[name] = &pair
	certCacheMu.Unlock()
	return &pair, nil
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

// countingConn считает байты, реально прочитанные до/во время TLS-рукопожатия.
type countingConn struct {
	net.Conn
	n *int64
}

func (c *countingConn) Read(b []byte) (int, error) {
	m, err := c.Conn.Read(b)
	if m > 0 {
		atomic.AddInt64(c.n, int64(m))
	}
	return m, err
}

// countWriter считает байты, реально записанные в направлении
// клиент→апстрим (c2uBytes) или апстрим→клиент (u2cBytes). Ответ на
// вопрос GPT «передаются ли данные в обе стороны».
type countWriter struct {
	w io.Writer
	n *int64
}

func (c countWriter) Write(b []byte) (int, error) {
	m, err := c.w.Write(b)
	if m > 0 {
		atomic.AddInt64(c.n, int64(m))
	}
	return m, err
}

// flowSeq — сквозной ID TCP:443 потока: каждое соединение логирует
// свой жизненный цикл строками "#ID ..." — по требованию GPT одна
// строка на этап: accepted / cliTLS / req+filter / upDial / upTLS / close.
var flowSeq int64

// handle443 — СОБСТВЕННЫЙ MITM-пайплайн (без goproxy): полная
// наблюдаемость всех этапов + блоклист + косметика.
func handle443(conn adapter.TCPConn, hp string) {
	fid := atomic.AddInt64(&flowSeq, 1)
	closeReason := "?"
	defer func() {
		if r := recover(); r != nil {
			setErr(fmt.Errorf("PANIC 443 %s: %v", hp, r))
			flowLog(fmt.Sprintf("#%d PANIC %v", fid, r))
		}
		flowLog(fmt.Sprintf("#%d close=%s", fid, closeReason))
		_ = conn.Close()
	}()
	atomic.AddInt64(&acceptedN, 1)
	fam := "v4"
	if strings.Contains(hp, ":") {
		fam = "v6" // GPT: семейство адреса в каждом соединении
	}
	flowLog(fmt.Sprintf("#%d dst=%s fam=%s accepted", fid, hp, fam))
	hostOnly := hp
	if i := strings.LastIndex(hp, ":"); i > 0 {
		hostOnly = hp[:i]
	}
	// DoH-эндпоинты: сырой туннель без MITM (иначе "unknown certificate",
	// т.к. клиент не доверяет нашему CA -> DNS умирает целиком)
	if DoHHosts[hostOnly] {
		up, err := dialTCP(hp)
		if err != nil {
			flowLog(fmt.Sprintf("#%d dohDial FAIL %v", fid, err))
			closeReason = "dohDialX"
			return
		}
		atomic.AddInt64(&dohPassN, 1)
		flowLog(fmt.Sprintf("#%d dohPass relay", fid))
		closeReason = "relay"
		relay(conn, up)
		return
	}
	var sni string
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"}, // только HTTP/1.1: h2 мы не говорим,
		// иначе бинарный preface "PRI * HTTP/2.0" не парсится http.ReadRequest
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			sni = hello.ServerName
			name := sni
			if name == "" {
				name = hostOnly
			}
			return certForName(name)
		},
	}
	var gotBytes int64
	tlsConn := tls.Server(&countingConn{Conn: conn, n: &gotBytes}, cfg)
	_ = tlsConn.SetDeadline(time.Now().Add(15 * time.Second))
	atomic.AddInt64(&cliHello, 1)
	if err := tlsConn.Handshake(); err != nil {
		gb := atomic.LoadInt64(&gotBytes)
		if errors.Is(err, io.EOF) && gb > 0 {
			// БЕНigner race: клиент прислал данные и корректно закрыл
			// соединение посреди рукопожатия. Chrome гоняет параллельные
			// коннекты и закрывает проигравшие — это НЕ ошибка сертификата
			// и не ошибка сети. Не трогаем ERR-строку.
			atomic.AddInt64(&cliTLSRace, 1)
			flowLog(fmt.Sprintf("#%d cliTLS race(%dB)", fid, gb))
			closeReason = "race"
			return
		}
		atomic.AddInt64(&cliTLSFail, 1)
		// bytes=0 + timeout => клиент просто молчит (не дело сертификата);
		// bytes>0 + alert unknown certificate => дело доверия CA
		setErr(fmt.Errorf("cliTLS %s bytes=%d: %w", hp, gb, err))
		flowLog(fmt.Sprintf("#%d cliTLS FAIL(%dB) sni=%q err=%v", fid, gb, sni, err))
		closeReason = "cliTLSfail"
		return
	}
	atomic.AddInt64(&cliTLSOk, 1)
	_ = tlsConn.SetDeadline(time.Time{})
	flowLog(fmt.Sprintf("#%d cliTLS ok sni=%q", fid, sni))
	closeReason = "cliClose"
	br := bufio.NewReader(tlsConn)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			es := err.Error()
			switch {
			case errors.Is(err, io.EOF) || strings.HasSuffix(es, "EOF"):
				// клиент закрыл соединение, ничего не запросив
				atomic.AddInt64(&normalEOF, 1)
				flowLog(fmt.Sprintf("#%d cli EOF no-req", fid))
				closeReason = "eof"
			case strings.Contains(es, "aborted"), strings.Contains(es, "closed"),
				strings.Contains(es, "reset by peer"), strings.Contains(es, "connection reset"):
				// Chrome резко закрыл неиспользованное/preconnect-соединение.
				// Норма для параллельных коннектов — НЕ ошибка тракта.
				atomic.AddInt64(&normalEOF, 1)
				flowLog(fmt.Sprintf("#%d cli aborted idle/preconnect", fid))
				closeReason = "cliAbort"
			default:
				setErr(fmt.Errorf("cliRead %s: %w", hp, err))
				flowLog(fmt.Sprintf("#%d cliRead FAIL err=%v", fid, err))
				closeReason = "cliReadX"
			}
			return
		}
		atomic.AddInt64(&httpReqN, 1)
		host := req.Host
		if host == "" {
			continue
		}
		path := req.URL.Path
		if len(path) > 80 {
			path = path[:80]
		}
		ref := req.Header.Get("Referer")
		if len(ref) > 50 {
			ref = ref[:50]
		}
		// ADSOURCE: явная пометка обращений к рекламной системе (GPT).
		// Домены рекламодателей (rsvx.ru, myrecruit.ru и т.п.) сюда НЕ входят.
		yad := isYandexAdHost(host)
		if yad {
			flowLog(fmt.Sprintf("#%d ADSOURCE host=%s path=%s method=%s", fid, host, path, req.Method))
		}
		blocked, rule := checkURL(req.Host, req.URL.Path)
		if blocked {
			atomic.AddInt64(&blockedN, 1)
			reason := rule
			if yad {
				reason = "YANDEX_AD_SOURCE:" + rule
			}
			flowLog(fmt.Sprintf("#%d req %s host=%s path=%s ref=%q FILTER=BLOCK rule=%q reason=%s", fid, req.Method, host, path, ref, rule, reason))
			resp := &http.Response{StatusCode: 403, Status: "403 Forbidden", Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), ContentLength: 0, Close: true}
			resp.Header.Set("Content-Type", "text/html")
			_ = resp.Write(countWriter{w: tlsConn, n: &u2cBytes})
			closeReason = "blocked:" + rule
			return
		}
		atomic.AddInt64(&allowN, 1)
		flowLog(fmt.Sprintf("#%d req %s host=%s path=%s ref=%q FILTER=allow", fid, req.Method, host, path, ref))
		// ADS? — эвристическая пометка потенциально рекламных запросов.
		// Блокирует НИЧЕГО, только подсвечивает в журнале для анализа.
		if r := adSuspicion(req.Host, req.URL.Path); r != "" {
			flowLog(fmt.Sprintf("#%d ADS? host=%s path=%s reason=%s", fid, host, path, r))
		}
		serverName := strings.Split(host, ":")[0]

		// Апстрим — по ИСХОДНОМУ IP назначения из TUN (hp). DNS не нужен:
		// браузер уже резолвил этот IP, а резолвер gomobile системного
		// resolv.conf в VPN-контексте не видит.
		up, err := dialTCP(hp)
		if err != nil {
			// Резерв: DoT-резолв имени из Host (тот же путь, что у самотеста)
			ip, lerr := lookupA(serverName)
			if lerr != nil {
				atomic.AddInt64(&upDialFail, 1)
				setErr(fmt.Errorf("upDial %s: %v / %v", hp, err, lerr))
				flowLog(fmt.Sprintf("#%d upDial FAIL %v/%v", fid, err, lerr))
				write502(tlsConn)
				closeReason = "upDialX"
				return
			}
			up, err = dialTCP(net.JoinHostPort(ip, "443"))
			if err != nil {
				atomic.AddInt64(&upDialFail, 1)
				setErr(fmt.Errorf("upDial %s: %w", hp, err))
				flowLog(fmt.Sprintf("#%d upDial FAIL %v", fid, err))
				write502(tlsConn)
				closeReason = "upDialX"
				return
			}
		}
		atomic.AddInt64(&upDialOk, 1)
		flowLog(fmt.Sprintf("#%d upDial ok %s", fid, hp))
		upTLS := tls.Client(up, &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12})
		if err := upTLS.Handshake(); err != nil {
			atomic.AddInt64(&upTLSFail, 1)
			setErr(fmt.Errorf("upTLS %s: %w", serverName, err))
			flowLog(fmt.Sprintf("#%d upTLS FAIL %v", fid, err))
			_ = up.Close()
			write502(tlsConn)
			closeReason = "upTLSX"
			return
		}
		atomic.AddInt64(&upTLSOk, 1)
		flowLog(fmt.Sprintf("#%d upTLS ok", fid))
		req.URL.Scheme = "https"
		if strings.Contains(host, ":") {
			req.URL.Host = host
		} else {
			req.URL.Host = host + ":443"
		}
		req.RequestURI = ""
		req.Header.Del("Proxy-Connection")
		req.Header.Del("Proxy-Authenticate")
		req.Header.Del("Proxy-Authorization")
		if err := req.Write(countWriter{w: upTLS, n: &c2uBytes}); err != nil {
			flowLog(fmt.Sprintf("#%d reqWrite FAIL %v", fid, err))
			_ = up.Close()
			closeReason = "reqWriteX"
			return
		}
		resp, err := http.ReadResponse(bufio.NewReader(upTLS), req)
		if err != nil {
			_ = up.Close()
			setErr(fmt.Errorf("upRead %s: %w", serverName, err))
			flowLog(fmt.Sprintf("#%d upRead FAIL %v", fid, err))
			write502(tlsConn)
			closeReason = "upReadX"
			return
		}
		atomic.AddInt64(&httpRespN, 1)
		resp = filterHTML(resp)
		werr := resp.Write(countWriter{w: tlsConn, n: &u2cBytes})
		_ = resp.Body.Close() // явное закрытие: без него течёт апстрим-TLS
		_ = up.Close()
		if werr != nil {
			flowLog(fmt.Sprintf("#%d respWrite FAIL %v", fid, werr))
			closeReason = "respWriteX"
			return
		}
		flowLog(fmt.Sprintf("#%d resp %d ok ct=%s", fid, resp.StatusCode, resp.Header.Get("Content-Type")))
		closeReason = "done"
		return // один запрос = одно соединение; Chrome открывает потоки параллельно
	}
}

func write502(w io.Writer) {
	// учитываем 502 в u2cBytes: это тоже байты апстрим→клиент
	_, _ = io.WriteString(countWriter{w: w, n: &u2cBytes}, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
}

// DNS через DNS-over-HTTPS: операторы РФ перехватывают/глушет plain
// UDP 53, поэтому апстрим — только по 443 в обход перехвата.
// DoH вручную поверх tlsDial (тот же проверенный путь дозвона, что и у
// самотеста) — http.Client в gomobile был непрозрачной точкой отказа.
var dohList = []struct {
	addr    string
	tlsName string
}{
	{"94.140.14.14:443", "dns.adguard-dns.com"},
	{"77.88.8.8:443", "common.dot.dns.yandex.net"},
}

func resolveDoH(query []byte) ([]byte, error) {
	var last error
	for _, ep := range dohList {
		conn, err := tlsDial(ep.addr, ep.tlsName)
		if err != nil {
			last = fmt.Errorf("doh-%s dial: %w", ep.tlsName, err)
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(6 * time.Second))
		head := fmt.Sprintf("POST /dns-query HTTP/1.1\r\nHost: %s\r\nContent-Type: application/dns-message\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", ep.tlsName, len(query))
		if _, err := conn.Write([]byte(head)); err != nil {
			_ = conn.Close()
			last = fmt.Errorf("doh-%s write-head: %w", ep.tlsName, err)
			continue
		}
		if _, err := conn.Write(query); err != nil {
			_ = conn.Close()
			last = fmt.Errorf("doh-%s write: %w", ep.tlsName, err)
			continue
		}
		br := bufio.NewReader(conn)
		status, err := br.ReadString('\n')
		if err != nil {
			_ = conn.Close()
			last = fmt.Errorf("doh-%s status-read: %w", ep.tlsName, err)
			continue
		}
		if !strings.Contains(status, "200") {
			_ = conn.Close()
			last = fmt.Errorf("doh-%s status: %s", ep.tlsName, strings.TrimSpace(status))
			continue
		}
		clen := -1
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				break
			}
			if line == "\r\n" {
				break
			}
			if strings.HasPrefix(strings.ToLower(line), "content-length:") {
				fmt.Sscanf(strings.TrimSpace(line[15:]), "%d", &clen)
			}
		}
		var resp []byte
		if clen > 0 && clen < 16384 {
			resp = make([]byte, clen)
			if _, err := io.ReadFull(br, resp); err != nil {
				_ = conn.Close()
				last = fmt.Errorf("doh-%s body: %w", ep.tlsName, err)
				continue
			}
		} else {
			resp, err = io.ReadAll(br)
			_ = err
		}
		_ = conn.Close()
		if len(resp) >= 12 {
			return resp, nil
		}
		last = fmt.Errorf("doh-%s short(%d)", ep.tlsName, len(resp))
	}
	if last == nil {
		last = errors.New("DoH: нет эндпоинтов")
	}
	return nil, last
}

// Апстримы, доступные из РФ: AdGuard DNS и Яндекс.
var udpUpstreams = []string{"94.140.14.14:53", "77.88.8.8:53", "8.8.8.8:53"}

// DoT-эндпоинты (порт 853).
var dotEndpoints = []struct {
	addr string
	name string
}{
	{"94.140.14.14:853", "dns.adguard-dns.com"},
	{"77.88.8.8:853", "common.dot.dns.yandex.net"},
}

// Кэш DNS-ответов: снижает зависимость от живости апстримов в конкретную секунду.
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
		// один write вместо двух: отдельные TCP-сегменты префикс+payload
		// рвали соединение у части DoT-серверов (read-hdr: EOF в логе)
		if _, err := conn.Write(append(lb[:], query...)); err != nil {
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

	// ВСЕ UDP-потоки — в журнал одной строкой с dst (диагностика GPT:
	// где именно ходит браузер, ничего не пропуская мимо наблюдения).
	// Счётчики: udpTry = ВСЕ UDP-пакеты, udpSeen = уникальные потоки UDP.
	atomic.AddInt64(&udpSeen, 1)
	ufam := "v4"
	if strings.Contains(id.LocalAddress.String(), ":") {
		ufam = "v6"
	}
	flowLog(fmt.Sprintf("udp dst=%s:%d fam=%s", id.LocalAddress.String(), id.LocalPort, ufam))

	// UDP/443 (QUIC/HTTP3): НЕ пропускаем напрямую — иначе рекламный
	// трафик уходит по HTTP/3 МИМО MITM (тракт TLS+HTTP его не видит).
	// Браузер откатывается на TCP/443 -> уже рабочий MITM-пайплайн.
	if id.LocalPort == 443 {
		atomic.AddInt64(&quicDrops, 1)
		return
	}
	// прочий UDP: прямой релей в апстрим (dst из заголовка потока)
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
