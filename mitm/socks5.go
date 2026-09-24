package mitm

// Локальный SOCKS5 (transport-core-v2, этап 1): ЧИСТЫЙ direct-outbound
// поверх protected-сокетов. НИКАКОЙ блокировки, MITM, фильтрации.
// HEV (hev-socks5-tunnel) гонит весь TUN-трафик сюда, мы просто
// достукиваемся до реального назначения.

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	localSocksLn   net.Listener
	localSocksMu   sync.Mutex
	localSocksTCPN int64
	localSocksUDPN int64
)

var (
	contentMitmN    int64
	contentMitmErrN int64
)

// ContentStats - статистика selective content-слоя (dzen).
func ContentStats() string {
	return "CONTENT_MITM=" + strconv.FormatInt(atomic.LoadInt64(&contentMitmN), 10) +
		" CONTENT_MITM_ERR=" + strconv.FormatInt(atomic.LoadInt64(&contentMitmErrN), 10)
}

// SocksStats — строка для экрана статистики.
func SocksStats() string {
	return "socks5 tcp=" + strconv.FormatInt(atomic.LoadInt64(&localSocksTCPN), 10) +
		" udp=" + strconv.FormatInt(atomic.LoadInt64(&localSocksUDPN), 10)
}

// StartSocks5 поднимает локальный SOCKS5 (CONNECT + UDP ASSOCIATE).
func StartSocks5(addr string) error {
	localSocksMu.Lock()
	defer localSocksMu.Unlock()
	if localSocksLn != nil {
		return nil
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	localSocksLn = ln
	go socksAcceptLoop(ln)
	return nil
}

// StopSocks5 останавливает сервер.
func StopSocks5() {
	localSocksMu.Lock()
	defer localSocksMu.Unlock()
	if localSocksLn != nil {
		_ = localSocksLn.Close()
		localSocksLn = nil
	}
}

func socksAcceptLoop(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go socksHandleConn(c)
	}
}

func socksHandleConn(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	head := make([]byte, 2)
	if _, err := io.ReadFull(c, head); err != nil || head[0] != 5 {
		return
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	if _, err := c.Write([]byte{5, 0}); err != nil {
		return
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil || req[0] != 5 {
		return
	}
	host, port, err := socksReadAddr(c, req[3])
	if err != nil {
		return
	}
	target := net.JoinHostPort(host, strconv.Itoa(port))
	switch req[1] {
	case 1: // CONNECT
		filtering := atomic.LoadInt32(&transportFiltering) == 1
		if filtering {
			if hit, _ := checkURL(host, ""); hit {
				atomic.AddInt64(&transportBlocked, 1)
				_, _ = c.Write([]byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0})
				return
			}
			if port == 53 {
				_, _ = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				transportTCPDNS(c)
				return
			}
		}
		up, err := dialTCP(target)
		if err != nil {
			_, _ = c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
			return
		}
		defer up.Close()
		if _, err := c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
			return
		}
		atomic.AddInt64(&localSocksTCPN, 1)
		_ = c.SetDeadline(time.Time{})
		if filtering && port == 443 {
			raw, sni, _, _ := peekClientHello(c)
			// Рекламные домены Google/Yandex — blocklist ДО любого pinned/direct
			if hit, rule := checkURL(sni, ""); sni != "" && hit {
				flowLog("HTTPS_BLOCK sni=" + sni + " rule=" + rule)
				atomic.AddInt64(&transportBlocked, 1)
				return
			}
			// 217: любые dzen-related host'ы, идущие мимо MITM - в лог
			if sni != "" && strings.Contains(sni, "dzen") && !isDzenHost(sni) {
				flowLog("DZEN_RELATED_HOST host=" + target + " sni=" + sni)
			}
			// 2.0.7 (209): selective content-MITM на СОБСТВЕННОМ коде
			// (certForName + sniffConn + bypassCache, без goproxy).
			// Fail-open на каждом этапе; TLS-отказ -> bypass -> direct.
			if isDzenHost(sni) {
				if handled, ok := handleDzenMITM(c, sni, raw); handled {
					if ok {
						atomic.AddInt64(&contentMitmN, 1)
					} else {
						atomic.AddInt64(&contentMitmErrN, 1)
					}
					return
				}
				// handled=false -> bypass: обычный direct ниже
			}
			// Universal V1: generic MITM для ЛЮБОГО непустого SNI.
			// Все решения block/DoH/pinned/runtime-bypass — только внутри handleGenericMITM.
			if sni != "" {
				if handled, ok := handleGenericMITM(c, sni, raw); handled {
					if ok {
						atomic.AddInt64(&genericMitmOKN, 1)
					} else {
						atomic.AddInt64(&genericMitmFailN, 1)
					}
					return
				}
				atomic.AddInt64(&genericDirectBypassN, 1)
				flowLog("GENERIC_DIRECT_BYPASS sni=" + sni + " reason=mitm-fail")
			}
			if len(raw) > 0 {
				if _, err := up.Write(raw); err != nil {
					return
				}
			}
		}
		socksRelay(c, up)
	case 3: // UDP ASSOCIATE
		uconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
		if err != nil {
			_, _ = c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
			return
		}
		defer uconn.Close()
		uport := uconn.LocalAddr().(*net.UDPAddr).Port
		resp := []byte{5, 0, 0, 1, 127, 0, 0, 1, byte(uport >> 8), byte(uport)}
		if _, err := c.Write(resp); err != nil {
			return
		}
		atomic.AddInt64(&localSocksUDPN, 1)
		_ = c.SetDeadline(time.Time{})
		socksHandleUDP(c, uconn)
	default:
		_, _ = c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
	}
}

func socksReadAddr(c io.Reader, atyp byte) (string, int, error) {
	var host string
	var port int
	switch atyp {
	case 1:
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return "", 0, err
		}
		host = net.IP(b).String()
	case 4:
		b := make([]byte, 16)
		if _, err := io.ReadFull(c, b); err != nil {
			return "", 0, err
		}
		host = net.IP(b).String()
	case 3:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(c, lb); err != nil {
			return "", 0, err
		}
		b := make([]byte, int(lb[0]))
		if _, err := io.ReadFull(c, b); err != nil {
			return "", 0, err
		}
		host = string(b)
	default:
		return "", 0, fmt.Errorf("bad atyp %d", atyp)
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(c, pb); err != nil {
		return "", 0, err
	}
	port = int(pb[0])<<8 | int(pb[1])
	return host, port, nil
}

func socksRelay(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(a, b)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(b, a)
		done <- struct{}{}
	}()
	<-done
}

func socksHandleUDP(ctrl net.Conn, u *net.UDPConn) {
	upstreams := make(map[string]net.Conn)
	var sender *net.UDPAddr
	defer func() {
		for _, up := range upstreams {
			_ = up.Close()
		}
	}()
	go func() {
		one := make([]byte, 1)
		_, _ = ctrl.Read(one)
		_ = u.Close()
		// Wake the owner loop; only that loop may access upstreams.
		// Its deferred cleanup closes all outbound sockets.
	}()
	buf := make([]byte, 64*1024)
	for {
		_ = u.SetReadDeadline(time.Now().Add(120 * time.Second))
		n, addr, err := u.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if sender == nil {
			sender = addr
		}
		payload, host, port, ok := socksParseUDPDatagram(buf[:n])
		if !ok {
			continue
		}
		if atomic.LoadInt32(&transportFiltering) == 1 {
			if port == 53 {
				select {
				case transportDNSWorkers <- struct{}{}:
					query := append([]byte(nil), payload...)
					go func(query []byte, host string, port int, addr *net.UDPAddr) {
						defer func() { <-transportDNSWorkers }()
						if ans := transportDNSReply(query); len(ans) > 0 {
							_, _ = u.WriteToUDP(socksBuildUDPDatagram(host, port, ans), addr)
						}
					}(query, host, port, addr)
				default:
					atomic.AddInt64(&transportErrors, 1)
					if ans := transportDNSError(payload, 2); len(ans) > 0 {
						_, _ = u.WriteToUDP(socksBuildUDPDatagram(host, port, ans), addr)
					}
				}
				continue
			}
			if port == 443 {
				atomic.AddInt64(&transportQUIC, 1)
				continue
			}
		}
		key := net.JoinHostPort(host, strconv.Itoa(port))
		up, exists := upstreams[key]
		if !exists {
			conn, err := dialUDP(key)
			if err != nil {
				continue
			}
			up = conn
			upstreams[key] = conn
			go socksPumpUDPDown(u, sender, conn, host, port)
		}
		_, _ = up.Write(payload)
	}
}

func socksPumpUDPDown(client *net.UDPConn, sender *net.UDPAddr, up net.Conn, host string, port int) {
	defer up.Close()
	buf := make([]byte, 64*1024)
	for {
		_ = up.SetReadDeadline(time.Now().Add(120 * time.Second))
		n, err := up.Read(buf)
		if err != nil {
			return
		}
		pkt := socksBuildUDPDatagram(host, port, buf[:n])
		_, _ = client.WriteToUDP(pkt, sender)
	}
}

func socksParseUDPDatagram(b []byte) ([]byte, string, int, bool) {
	if len(b) < 10 || b[2] != 0 {
		return nil, "", 0, false
	}
	host, port, hdrLen, ok := socksParseAddrBytes(b, 3)
	if !ok {
		return nil, "", 0, false
	}
	return b[hdrLen:], host, port, true
}

func socksBuildUDPDatagram(host string, port int, payload []byte) []byte {
	h := make([]byte, 0, 24)
	h = append(h, 0, 0, 0)
	ip := net.ParseIP(host)
	if ip4 := ip.To4(); ip4 != nil {
		h = append(h, 1)
		h = append(h, ip4...)
	} else if ip16 := ip.To16(); ip16 != nil {
		h = append(h, 4)
		h = append(h, ip16...)
	} else {
		h = append(h, 3, byte(len(host)))
		h = append(h, host...)
	}
	h = append(h, byte(port>>8), byte(port))
	return append(h, payload...)
}

func socksParseAddrBytes(b []byte, off int) (string, int, int, bool) {
	if off >= len(b) {
		return "", 0, 0, false
	}
	atyp := b[off]
	off++
	var host string
	switch atyp {
	case 1:
		if off+4 > len(b) {
			return "", 0, 0, false
		}
		host = net.IP(b[off : off+4]).String()
		off += 4
	case 4:
		if off+16 > len(b) {
			return "", 0, 0, false
		}
		host = net.IP(b[off : off+16]).String()
		off += 16
	case 3:
		if off >= len(b) {
			return "", 0, 0, false
		}
		l := int(b[off])
		off++
		if off+l > len(b) {
			return "", 0, 0, false
		}
		host = string(b[off : off+l])
		off += l
	default:
		return "", 0, 0, false
	}
	if off+2 > len(b) {
		return "", 0, 0, false
	}
	port := int(b[off])<<8 | int(b[off+1])
	off += 2
	return host, port, off, true
}


// socksDispatchDzen - SELECTIVE content 2.0.3: поток dzen уводим в
// локальный goproxy (CONNECT + replay перехваченного ClientHello).
func socksDispatchDzen(c net.Conn, sni string, raw []byte) bool {
	flowLog("DZEN_MITM_BEGIN host=" + sni)
	// 2.0.5: dialLocal - локальный 127.0.0.1 proxy НЕ проходит protect()
	pconn, err := dialLocal(proxyCurAddr())
	if err != nil {
		flowLog("DZEN_MITM_FAIL dial:" + err.Error())
		return false
	}
	flowLog("DZEN_PROXY_CONNECTED")
	_ = pconn.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := fmt.Fprintf(pconn, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", sni, sni); err != nil {
		_ = pconn.Close()
		flowLog("DZEN_MITM_FAIL connect-write:" + err.Error())
		return false
	}
	br := bufio.NewReader(pconn)
	status, err := br.ReadString('\n')
	if err != nil || !strings.Contains(status, " 200") {
		_ = pconn.Close()
		flowLog("DZEN_MITM_FAIL status:" + strings.TrimSpace(status))
		return false
	}
	flowLog("DZEN_PROXY_200")
	for {
		line, lerr := br.ReadString('\n')
		if lerr != nil || line == "\r\n" || line == "\n" {
			break
		}
	}
	_ = pconn.SetDeadline(time.Time{})
	if _, err := pconn.Write(raw); err != nil {
		_ = pconn.Close()
		flowLog("DZEN_MITM_FAIL hello-replay:" + err.Error())
		return false
	}
	flowLog("DZEN_HELLO_REPLAY_OK")
	socksRelay(c, pconn)
	flowLog("DZEN_MITM_DONE host=" + sni)
	return true
}
