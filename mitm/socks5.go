package mitm

// Локальный SOCKS5 (transport-core-v2, этап 1): ЧИСТЫЙ direct-outbound
// поверх protected-сокетов. НИКАКОЙ блокировки, MITM, фильтрации.
// HEV (hev-socks5-tunnel) гонит весь TUN-трафик сюда, мы просто
// достукиваемся до реального назначения.

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

var (
	socksLn   net.Listener
	socksMu   sync.Mutex
	socksTCPN int64
	socksUDPN int64
)

// SocksStats — строка для экрана статистики.
func SocksStats() string {
	return "socks5 tcp=" + strconv.FormatInt(atomic.LoadInt64(&socksTCPN), 10) +
		" udp=" + strconv.FormatInt(atomic.LoadInt64(&socksUDPN), 10)
}

// StartSocks5 поднимает локальный SOCKS5 (CONNECT + UDP ASSOCIATE).
func StartSocks5(addr string) error {
	socksMu.Lock()
	defer socksMu.Unlock()
	if socksLn != nil {
		return nil
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	socksLn = ln
	go socksAcceptLoop(ln)
	return nil
}

// StopSocks5 останавливает сервер.
func StopSocks5() {
	socksMu.Lock()
	defer socksMu.Unlock()
	if socksLn != nil {
		_ = socksLn.Close()
		socksLn = nil
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
		up, err := dialTCP(target)
		if err != nil {
			_, _ = c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
			return
		}
		defer up.Close()
		if _, err := c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
			return
		}
		atomic.AddInt64(&socksTCPN, 1)
		_ = c.SetDeadline(time.Time{})
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
		atomic.AddInt64(&socksUDPN, 1)
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
		for _, up := range upstreams {
			_ = up.Close()
		}
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
		key := net.JoinHostPort(host, strconv.Itoa(port))
		up, exists := upstreams[key]
		if !exists {
			conn, err := dialUDP(key)
			if err != nil {
				continue
			}
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
