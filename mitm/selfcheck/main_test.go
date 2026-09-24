package selfcheck

import (
	"os"
	"strings"
	"testing"
)

func TestNoDangerousSelectors(t *testing.T) {
	data, err := os.ReadFile("../../app/src/main/assets/generic_cosmetic_rules.txt")
	if err != nil {
		t.Skip("asset not found")
	}
	for _, line := range strings.Split(string(data), "\n") {
		l := strings.TrimSpace(line)
		if l == "" || strings.HasPrefix(l, "!") {
			continue
		}
		sel := strings.SplitN(l, "##", 2)
		if len(sel) == 2 {
			l = sel[1]
		}
		lower := strings.ToLower(l)
		if strings.Contains(lower, "class*=banner") || strings.Contains(lower, "id*=banner") ||
			strings.Contains(lower, "class*=ad") || strings.Contains(lower, "class*=promo") ||
			strings.Contains(lower, "id*=promo") {
			t.Errorf("dangerous selector in generic_cosmetic_rules.txt: %s", l)
		}
	}
}

func TestFilterProviderRules(t *testing.T) {
	data, err := os.ReadFile("../../app/src/main/assets/blocklist.txt")
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
