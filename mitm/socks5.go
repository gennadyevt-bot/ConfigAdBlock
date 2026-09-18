package mitm

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// SOCKS5-шим между tun2socks и MITM-прокси. tun2socks полноценно
// поддерживает только SOCKS5. TCP 443 -> цепочка в goproxy (MITM+фильтры),
// остальные порты — напрямую (plain HTTP через MITM ломался бы). UDP 53
// (DNS) ретранслируем в 8.8.8.8 — приложение исключено из VPN.
const socks5Addr = "127.0.0.1:1080"

var (
	socksMu  sync.Mutex
	socksSrv *socks5Server

	tcpCount  int64
	udpCount  int64
	directCnt int64
	tcpTry    int64
	udpTry    int64
	dnsGot    int64

	errMu      sync.Mutex
	lastErrStr string
)

// setErr запоминает последнюю ошибку движка (видна на экране приложения).
func setErr(e error) {
	if e == nil {
		return
	}
	errMu.Lock()
	lastErrStr = e.Error()
	errMu.Unlock()
}

// LastErr возвращает последнюю ошибку движка (пусто, если всё чисто).
func LastErr() string {
	errMu.Lock()
	defer errMu.Unlock()
	return lastErrStr
}

// Счётчики для самотеста на главном экране приложения.
func TcpCount() int64  { return atomic.LoadInt64(&tcpCount) }
func UdpCount() int64  { return atomic.LoadInt64(&udpCount) }
func DirectCount() int64 { return atomic.LoadInt64(&directCnt) }
func TcpTry() int64     { return atomic.LoadInt64(&tcpTry) }
func UdpTry() int64     { return atomic.LoadInt64(&udpTry) }
func DnsGot() int64    { return atomic.LoadInt64(&dnsGot) }
func GpOkExt() int64   { return atomic.LoadInt64(&gpOk) }
func GpFailExt() int64 { return atomic.LoadInt64(&gpFail) }
func GpDialExt() int64 { return atomic.LoadInt64(&gpDial) }

type socks5Server struct {
	ln  net.Listener
	udp *net.UDPConn
}

func startSocks5() error {
	socksMu.Lock()
	defer socksMu.Unlock()
	if socksSrv != nil {
		return errors.New("socks5 already running")
	}
	ln, err := net.Listen("tcp", socks5Addr)
	if err != nil {
		return err
	}
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		_ = ln.Close()
		return err
	}
	s := &socks5Server{ln: ln, udp: uc}
	socksSrv = s
	go s.tcpLoop()
	go s.udpLoop()
	log.Printf("[MITM] socks5 on %s, udp relay %s", socks5Addr, uc.LocalAddr())
	return nil
}

func stopSocks5() {
	socksMu.Lock()
	defer socksMu.Unlock()
	if socksSrv != nil {
		_ = socksSrv.ln.Close()
		_ = socksSrv.udp.Close()
		socksSrv = nil
	}
}

func (s *socks5Server) tcpLoop() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handleTCP(c)
	}
}

// Счётчики DIRECT-релея (матрица GPT: dialOK+TX>0+RX=0 => ответ не
// возвращается; TX=0 => клиент ничего не отправил после коннекта).
var (
	dirTx int64
	dirRx int64
)

func DirTx() int64 { return atomic.LoadInt64(&dirTx) }
func DirRx() int64 { return atomic.LoadInt64(&dirRx) }

func relay(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { n, _ := io.Copy(a, b); if n > 0 { atomic.AddInt64(&dirTx, n) }; wg.Done() }()
	go func() { n, _ := io.Copy(b, a); if n > 0 { atomic.AddInt64(&dirRx, n) }; wg.Done() }()
	wg.Wait()
	_ = a.Close()
	_ = b.Close()
}

func (s *socks5Server) handleTCP(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))

	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil || hdr[0] != 5 {
		return
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	if _, err := c.Write([]byte{5, 0}); err != nil { // NO AUTH
		return
	}

	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil || req[0] != 5 {
		return
	}
	cmd := req[1]
	var host string
	switch req[3] {
	case 1:
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 3:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(c, lb); err != nil {
			return
		}
		db := make([]byte, int(lb[0]))
		if _, err := io.ReadFull(c, db); err != nil {
			return
		}
		host = string(db)
	default:
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(c, pb); err != nil {
		return
	}
	port := int(pb[0])<<8 | int(pb[1])

	if cmd != 1 && cmd != 3 {
		_, _ = c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}

	if cmd == 3 { // UDP ASSOCIATE
		uport := s.udp.LocalAddr().(*net.UDPAddr).Port
		_, _ = c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, byte(uport >> 8), byte(uport)})
		_ = c.SetDeadline(time.Time{})
		_, _ = io.Copy(io.Discard, c)
		return
	}

	// CONNECT. Только 443 идёт через MITM (там TLS и фильтры); остальное —
	// прямое соединение, иначе plain HTTP ломался бы попыткой TLS.
	if port != 443 {
		up, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprint(port)), 10*time.Second)
		if err != nil {
			_, _ = c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
			return
		}
		_, _ = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		atomic.AddInt64(&directCnt, 1)
		_ = c.SetDeadline(time.Time{})
		relay(c, up)
		return
	}

	g, err := dialTCP(proxyCurAddr())
	if err != nil {
		_, _ = c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	_, _ = fmt.Fprintf(g, "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n", host, port, host, port)
	br := bufio.NewReader(g)
	status, err := br.ReadString('\n')
	if err != nil || !strings.Contains(status, "200") {
		_ = g.Close()
		_, _ = c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
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
	_, _ = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	atomic.AddInt64(&tcpCount, 1)
	_ = c.SetDeadline(time.Time{})
	if br.Buffered() > 0 {
		_, _ = io.CopyN(c, br, int64(br.Buffered()))
	}
	relay(c, g)
}

func (s *socks5Server) udpLoop() {
	buf := make([]byte, 64*1024)
	for {
		n, client, err := s.udp.ReadFromUDP(buf)
		if err != nil {
			return
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		go s.handleUDP(pkt, client)
	}
}

func (s *socks5Server) handleUDP(pkt []byte, client *net.UDPAddr) {
	if len(pkt) < 10 || pkt[2] != 0 {
		return
	}
	var target string
	off := 4
	switch pkt[3] {
	case 1:
		ip := net.IP(pkt[4:8])
		off = 8
		port := int(pkt[off])<<8 | int(pkt[off+1])
		off += 2
		if ip.String() == "10.0.0.2" {
			ip = net.ParseIP("8.8.8.8")
		}
		if port != 53 {
			return
		}
		target = net.JoinHostPort(ip.String(), "53")
	case 3:
		if len(pkt) < 5 {
			return
		}
		l := int(pkt[4])
		if len(pkt) < 5+l+2 {
			return
		}
		domain := string(pkt[5 : 5+l])
		off = 5 + l
		port := int(pkt[off])<<8 | int(pkt[off+1])
		off += 2
		if port != 53 {
			return
		}
		target = net.JoinHostPort(domain, "53")
	default:
		return
	}
	payload := pkt[off:]

	rconn, err := net.DialTimeout("udp", target, 5*time.Second)
	if err != nil {
		return
	}
	defer rconn.Close()
	_ = rconn.SetDeadline(time.Now().Add(5*time.Second))
	if _, err := rconn.Write(payload); err != nil {
		return
	}
	rbuf := make([]byte, 4096)
	rn, err := rconn.Read(rbuf)
	if err != nil {
		return
	}
	atomic.AddInt64(&udpCount, 1)
	raddr, _ := net.ResolveUDPAddr("udp", target)
	out := make([]byte, 0, rn+10)
	out = append(out, 0, 0, 0, 1)
	out = append(out, raddr.IP.To4()...)
	out = append(out, byte(raddr.Port>>8), byte(raddr.Port))
	out = append(out, rbuf[:rn]...)
	_, _ = s.udp.WriteToUDP(out, client)
}
