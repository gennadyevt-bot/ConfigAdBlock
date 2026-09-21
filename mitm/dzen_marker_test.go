package mitm

import "testing"

// Self-check (230): маркер рекламы Дзена — нормализация и совпадения.
// Обычный текст статей НЕ должен совпадать.
func TestDzenAdMarker(t *testing.T) {
	trueCases := []string{
		"Реклама", "реклама",
		"Реклама 16+", "Реклама 18+",
		"реклама · 16+", "реклама · 18+",
		"Реклама • 16+", "Реклама - 16+",
		"Соцреклама", "Соцреклама 18+",
	}
	for _, c := range trueCases {
		if !dzenAdMarkerRe.MatchString(c) {
			t.Errorf("must MATCH: %q", c)
		}
	}
	falseCases := []string{
		"Обычный текст статьи",
		"Рекламная статья про машины",
		"рекламный блок",
		"16+",
		"реклама16+",
		"не реклама",
	}
	for _, c := range falseCases {
		if dzenAdMarkerRe.MatchString(c) {
			t.Errorf("must NOT match: %q", c)
		}
	}
}
