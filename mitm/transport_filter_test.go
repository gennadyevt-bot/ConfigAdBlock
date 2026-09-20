package mitm

import (
	"bytes"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestTransportDNSBlock(t *testing.T) {
	p := filepath.Join(t.TempDir(), "rules.txt")
	if err := os.WriteFile(p, []byte("ads.example.test\nexample.test/ads/\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ConfigureTransportFilter(p)
	defer atomic.StoreInt32(&transportFiltering, 0)
	q := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 3, 'a', 'd', 's', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 4, 't', 'e', 's', 't', 0, 0, 1, 0, 1}
	// An EDNS record must not survive in an NXDOMAIN response with ARCOUNT=0.
	q = append(q, 0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 0)
	ans := transportDNSReply(q)
	if len(ans) != 34 || !bytes.Equal(ans[:2], q[:2]) || ans[3]&15 != 3 || ans[11] != 0 {
		t.Fatalf("bad DNS response: %x", ans)
	}
	if hit, _ := checkURL("example.test", ""); hit {
		t.Fatal("path rule blocked whole host")
	}
	if atomic.LoadInt64(&transportBlocked) != 1 {
		t.Fatal("block counter missing")
	}
	for _, q := range [][]byte{nil, {1, 2}, make([]byte, 12)} {
		if got := transportDNSError(q, 3); got != nil {
			t.Fatalf("accepted malformed query %x", q)
		}
	}
}
