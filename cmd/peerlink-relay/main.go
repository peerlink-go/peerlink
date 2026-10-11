package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/peerlink-go/peerlink/internal/relay"
	"github.com/peerlink-go/peerlink/internal/stun"
)

func main() {
	var (
		httpAddr = flag.String("listen", ":8443", "HTTP/WebSocket relay dinleme adresi")
		stunAddr = flag.String("stun", ":3478", "UDP STUN dinleme adresi (boş = kapalı)")
	)
	flag.Parse()

	log.Printf("PeerLink Relay & STUN Sunucusu başlatılıyor...")

	// 1. Start STUN UDP Listener if enabled
	if *stunAddr != "" {
		go runSTUNServer(*stunAddr)
	}

	// 2. Start Relay HTTP/WebSocket Server
	relaySrv := relay.NewServer(log.Printf)
	httpServer := &http.Server{
		Addr:    *httpAddr,
		Handler: relaySrv.Handler(),
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Printf("Relay servisi dinleniyor: %s", *httpAddr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP sunucu hatası: %v", err)
		}
	}()

	<-sigCh
	log.Println("Kapatılıyor...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	httpServer.Shutdown(ctx)
}

func runSTUNServer(addr string) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		log.Fatalf("STUN adres hatası: %v", err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("STUN UDP dinlenemedi: %v", err)
	}
	defer conn.Close()

	log.Printf("STUN sunucusu dinleniyor: %s", addr)
	buf := make([]byte, 1024)

	for {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n < 20 || !stun.IsSTUN(buf[:n]) {
			continue
		}

		var txID [12]byte
		copy(txID[:], buf[8:20])

		clientAddr, err := netip.ParseAddrPort(fmt.Sprintf("%s:%d", from.IP.String(), from.Port))
		if err != nil {
			continue
		}

		resp := stun.BuildResponse(txID, clientAddr)
		_, _ = conn.WriteToUDP(resp, from)
	}
}
