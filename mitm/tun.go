package mitm

import (
	"fmt"

	"github.com/xjasonlyu/tun2socks/v2/core/device/fdbased"
	"github.com/xjasonlyu/tun2socks/v2/engine"
)

// StartTunnel заворачивает трафик Android TUN-интерфейса (fd, полученный
// от VpnService.Builder.establish()) в локальный прокси движка.
// Вызывать ПОСЛЕ StartProxy — стек шлёт трафик на 127.0.0.1:8080.
func StartTunnel(fd int, mtu int) error {
	engine.Insert(&engine.Key{
		Device:   fmt.Sprintf("%s://%d", fdbased.Driver, fd),
		Proxy:    "http://" + proxyAddr,
		MTU:      mtu,
		LogLevel: "error",
	})
	engine.Start()
	return nil
}

// StopTunnel останавливает сетевой стек (закрывает fd — Android
// освободит TUN).
func StopTunnel() {
	engine.Stop()
}
