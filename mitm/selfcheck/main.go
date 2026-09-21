// Self-check (230): маркер рекламы Дзена — нормализация и совпадения.
// Обычный текст статей НЕ должен совпадать. Запускается в CI: go run ./selfcheck.
package main

import (
	"fmt"
	"os"

	"configadblock/mitm"
)

func main() {
	trueCases := []string{
		"Реклама", "реклама",
		"Реклама 16+", "Реклама 18+",
		"реклама · 16+", "реклама · 18+",
		"Реклама • 16+", "Реклама - 16+",
		"Соцреклама", "Соцреклама 18+",
	}
	falseCases := []string{
		"Обычный текст статьи",
		"Рекламная статья про машины",
		"рекламный блок",
		"16+",
		"не реклама",
	}
	fail := 0
	for _, c := range trueCases {
		if !mitm.DzenAdMarkerRe.MatchString(c) {
			fmt.Println("FAIL must MATCH:", c)
			fail++
		}
	}
	for _, c := range falseCases {
		if mitm.DzenAdMarkerRe.MatchString(c) {
			fmt.Println("FAIL must NOT match:", c)
			fail++
		}
	}
	if fail > 0 {
		os.Exit(1)
	}
	fmt.Printf("SELFCHECK OK: dzen marker regex, %d true / %d false cases\n", len(trueCases), len(falseCases))
}
