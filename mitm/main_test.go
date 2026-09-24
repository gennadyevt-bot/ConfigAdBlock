package mitm

import (
	"os"
	"strings"
	"testing"
)

// Universal V1: generic cosmetic rules не должны содержать опасных селекторов
func TestNoDangerousSelectors(t *testing.T) {
	data, err := os.ReadFile("../app/src/main/assets/generic_cosmetic_rules.txt")
	if err != nil {
		t.Skip("asset not found")
	}
	for _, line := range strings.Split(string(data), "\n") {
		l := strings.TrimSpace(line)
		if l == "" || strings.HasPrefix(l, "!") {
			continue
		}
		if strings.Contains(l, "##") {
			l = strings.SplitN(l, "##", 2)[1]
		}
		lower := strings.ToLower(l)
		if strings.Contains(lower, "class*=banner") || strings.Contains(lower, "id*=banner") ||
			strings.Contains(lower, "class*=ad") || strings.Contains(lower, "class*=promo") ||
			strings.Contains(lower, "id*=promo") {
			t.Errorf("dangerous selector: %s", l)
		}
	}
}

// Universal V1: blocklist должен давать ~49k валидных доменов
func TestBlocklistCount(t *testing.T) {
	data, err := os.ReadFile("../app/src/main/assets/blocklist.txt")
	if err != nil {
		t.Skip("blocklist not found")
	}
	count := 0
	for _, line := range strings.Split(string(data), "\n") {
		l := strings.TrimSpace(line)
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "!") {
			continue
		}
		if strings.HasPrefix(l, "0.0.0.0 ") || strings.HasPrefix(l, "127.0.0.1 ") {
			l = l[strings.Index(l, " ")+1:]
		}
		l = strings.TrimPrefix(l, "||")
		if strings.Contains(l, "^") || strings.Contains(l, "*") {
			l = strings.Split(strings.Split(l, "^")[0], "*")[0]
		}
		l = strings.TrimPrefix(l, "www.")
		if len(l) < 4 || len(l) > 253 || !strings.Contains(l, ".") || l == "localhost" {
			continue
		}
		count++
	}
	if count < 40000 {
		t.Errorf("expected ~49000 rules, got %d", count)
	}
}

// Universal V1: ALPN parser tests (4 обязательных случая)
func TestALPNParser(t *testing.T) {
	// Helper: build minimal ClientHello with ALPN extension
	buildCH := func(alpnList []string) []byte {
		var alpnBytes []byte
		for _, p := range alpnList {
			alpnBytes = append(alpnBytes, byte(len(p)))
			alpnBytes = append(alpnBytes, []byte(p)...)
		}
		listLen := len(alpnBytes)
		ext := []byte{0x00, 0x10, byte(listLen >> 8), byte(listLen & 0xFF), byte(listLen >> 8), byte(listLen & 0xFF)}
		ext = append(ext, alpnBytes...)
		// TLS record header + handshake header + version + random + sidLen(0) + ciphers(2) + comp(1) + extLen + ext
		body := []byte{0x03, 0x03} // version
		body = append(body, make([]byte, 32)...) // random
		body = append(body, 0) // sidLen
		body = append(body, 0, 2, 0x13, 0x01) // ciphersLen + cipher
		body = append(body, 1, 0) // compLen + comp
		body = append(body, byte(len(ext)>>8), byte(len(ext)&0xFF)) // extLen
		body = append(body, ext...)
		hs := []byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body) & 0xFF)}
		hs = append(hs, body...)
		rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs) & 0xFF)}
		rec = append(rec, hs...)
		return rec
	}

	cases := []struct {
		name     string
		alpn     []string
		expected string
	}{
		{"h2+http/1.1 -> MITM", []string{"h2", "http/1.1"}, "http/1.1"},
		{"http/1.1+h2 -> MITM", []string{"http/1.1", "h2"}, "http/1.1"},
		{"h2 only -> bypass", []string{"h2"}, "h2"},
		{"http/1.1 only -> MITM", []string{"http/1.1"}, "http/1.1"},
	}
	for _, tc := range cases {
		raw := buildCH(tc.alpn)
		got := peekClientHelloALPN(raw)
		if got != tc.expected {
			t.Errorf("%s: expected %q got %q", tc.name, tc.expected, got)
		}
	}
}

// Universal V1: generic cosmetic rules must load >0 selectors
func TestGenericCosmeticRulesCount(t *testing.T) {
	data, err := os.ReadFile("../app/src/main/assets/generic_cosmetic_rules.txt")
	if err != nil {
		t.Skip("asset not found")
	}
	count := 0
	for _, line := range strings.Split(string(data), "\n") {
		l := strings.TrimSpace(line)
		if l == "" || strings.HasPrefix(l, "!") {
			continue
		}
		count++
	}
	if count == 0 {
		t.Error("generic_cosmetic_rules.txt has 0 selectors after parsing")
	}
	t.Logf("generic_cosmetic_rules count=%d", count)
}
