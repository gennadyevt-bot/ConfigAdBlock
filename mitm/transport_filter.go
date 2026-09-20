package mitm

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"
)

var transportDNSWorkers = make(chan struct{}, 32)
var transportFiltering int32
var transportBlocked, transportDNS, transportErrors, transportQUIC int64

func ConfigureTransportFilter(path string) {
	loadBlocklist(path)
	atomic.StoreInt64(&transportBlocked, 0)
	atomic.StoreInt64(&transportDNS, 0)
	atomic.StoreInt64(&transportErrors, 0)
	atomic.StoreInt64(&transportQUIC, 0)
	atomic.StoreInt64(&localSocksTCPN, 0)
	atomic.StoreInt64(&localSocksUDPN, 0)
	atomic.StoreInt32(&transportFiltering, 1)
}
func TransportFilterStats() string {
	return fmt.Sprintf("DNS запросы=%d | блокировки DNS/SNI=%d | ошибки DNS=%d | QUIC отклонён=%d\n%s", atomic.LoadInt64(&transportDNS), atomic.LoadInt64(&transportBlocked), atomic.LoadInt64(&transportErrors), atomic.LoadInt64(&transportQUIC), SocksStats())
}
func transportDNSReply(q []byte) []byte {
	atomic.AddInt64(&transportDNS, 1)
	host := dnsQueryDomain(q)
	if host == "" || len(q) < 12 {
		return nil
	}
	if hit, _ := checkURL(host, ""); hit {
		atomic.AddInt64(&transportBlocked, 1)
		return transportDNSError(q, 3)
	}
	ans, err := resolveDNS(q)
	if err != nil {
		atomic.AddInt64(&transportErrors, 1)
		return transportDNSError(q, 2)
	}
	return ans
}
func transportDNSError(q []byte, code byte) []byte {
	if len(q) < 12 {
		return nil
	}
	// Keep the question only, stripping EDNS and any additional records.
	end := 12
	for end < len(q) {
		n := int(q[end])
		end++
		if n == 0 {
			break
		}
		if n > 63 || end+n > len(q) {
			return nil
		}
		end += n
	}
	if end+4 > len(q) {
		return nil
	}
	end += 4
	r := append([]byte(nil), q[:end]...)
	r[2] = 0x80 | (q[2] & 1)
	r[3] = 0x80 | code
	r[4] = 0
	r[5] = 1
	for i := 6; i < 12; i++ {
		r[i] = 0
	}
	return r
}
func transportTCPDNS(c net.Conn) {
	for {
		c.SetDeadline(time.Now().Add(30 * time.Second))
		var hdr [2]byte
		if _, err := io.ReadFull(c, hdr[:]); err != nil {
			return
		}
		q := make([]byte, int(binary.BigEndian.Uint16(hdr[:])))
		if _, err := io.ReadFull(c, q); err != nil {
			return
		}
		ans := transportDNSReply(q)
		if len(ans) == 0 {
			return
		}
		binary.BigEndian.PutUint16(hdr[:], uint16(len(ans)))
		if _, err := c.Write(append(hdr[:], ans...)); err != nil {
			return
		}
	}
}
