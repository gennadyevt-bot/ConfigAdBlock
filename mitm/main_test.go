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
