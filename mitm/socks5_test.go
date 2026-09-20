package mitm

import (
	"bytes"
	"net"
	"testing"
	"time"
)

// The first packet to each new destination must use the newly dialled socket.
// Closing the control connection during traffic must not race with map writes.
func TestSocksUDPForwardAndClose(t *testing.T) {
	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		b := make([]byte, 2048)
		for {
			n, a, e := echo.ReadFromUDP(b)
			if e != nil {
				return
			}
			echo.WriteToUDP(b[:n], a)
		}
	}()
	for i := 0; i < 50; i++ {
		func() {
			relay, e := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if e != nil {
				t.Fatal(e)
			}
			defer relay.Close()
			client, e := net.DialUDP("udp", nil, relay.LocalAddr().(*net.UDPAddr))
			if e != nil {
				t.Fatal(e)
			}
			defer client.Close()
			ctrl, peer := net.Pipe()
			defer ctrl.Close()
			defer peer.Close()
			done := make(chan struct{})
			go func() { socksHandleUDP(ctrl, relay); close(done) }()
			payload := []byte("first UDP packet")
			port := echo.LocalAddr().(*net.UDPAddr).Port
			packet := socksBuildUDPDatagram("127.0.0.1", port, payload)
			client.SetDeadline(time.Now().Add(2 * time.Second))
			if _, e = client.Write(packet); e != nil {
				t.Fatal(e)
			}
			b := make([]byte, 2048)
			n, e := client.Read(b)
			if e != nil {
				t.Fatal(e)
			}
			got, _, _, ok := socksParseUDPDatagram(b[:n])
			if !ok || !bytes.Equal(got, payload) {
				t.Fatalf("bad UDP reply: %q", b[:n])
			}
			sent := make(chan struct{})
			go func() {
				defer close(sent)
				for j := 0; j < 100; j++ {
					client.Write(socksBuildUDPDatagram("127.0.0.1", 20000+j, payload))
				}
			}()
			peer.Close()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("UDP shutdown stuck")
			}
			<-sent
		}()
	}
}
