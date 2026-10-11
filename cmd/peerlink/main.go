package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/peerlink-go/peerlink/internal/localapi"
)

func main() {
	if len(os.Args) < 2 {
		printHelp()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	client := localapi.NewClient("")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	switch cmd {
	case "up":
		cmdUp(ctx, client, args)
	case "down":
		cmdDown(ctx, client, args)
	case "status":
		cmdStatus(ctx, client, args)
	case "ip":
		cmdIP(ctx, client, args)
	case "ssh":
		cmdSSH(ctx, client, args)
	case "configure":
		cmdConfigure(args)
	case "version":
		fmt.Println("PeerLink v1.0.0 (darwin/arm64)")
	default:
		fmt.Fprintf(os.Stderr, "Bilinmeyen komut: %s\n\n", cmd)
		printHelp()
		os.Exit(1)
	}
}

func printHelp() {
	fmt.Println(`PeerLink Mesh VPN CLI

Kullanım:
  peerlink <komut> [seçenekler]

Komutlar:
  up        PeerLink ağına bağlanır veya ayarları günceller
  down      Bağlantıyı duraklatır/kapatır
  status    Ağ durumunu ve bağlı eşleri (peer) gösterir
  ip        Cihazın PeerLink IP adresini yazdırır
  ssh       PeerLink üzerinden güvenli SSH bağlantısı açar
  configure Yerel OpenSSH (~/.ssh/config) yapılandırmasını ayarlar
  logout    Cihazın oturumunu kapatır ve anahtarı siler
  version   Sürüm bilgisini gösterir

Daha fazla bilgi için 'peerlink <komut> -h' kullanın.`)
}

func cmdUp(ctx context.Context, client *localapi.Client, args []string) {
	fs := flag.NewFlagSet("up", flag.ExitOnError)
	authKey := fs.String("auth-key", "", "Ön onaylı kayıt anahtarı (auth key)")
	loginServer := fs.String("login-server", "", "Koordinasyon sunucusu adresi (örn: http://10.0.0.1:8080)")
	hostname := fs.String("hostname", "", "Ağda görünecek cihaz adı")
	ssh := fs.Bool("ssh", false, "PeerLink SSH sunucusunu etkinleştir")
	advertiseExitNode := fs.Bool("advertise-exit-node", false, "Bu cihazı çıkış düğümü (exit node) olarak tanıt")
	exitNode := fs.String("exit-node", "", "Kullanılacak çıkış düğümü adı veya IP'si")
	fs.Parse(args)

	req := localapi.UpRequest{
		AuthKey:           *authKey,
		ControlURL:        *loginServer,
		Hostname:          *hostname,
		SSH:               *ssh,
		AdvertiseExitNode: *advertiseExitNode,
		ExitNode:          *exitNode,
	}

	resp, err := client.Up(ctx, req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Hata: %v\n", err)
		os.Exit(1)
	}

	if resp.AuthURL != "" {
		fmt.Printf("\nLütfen cihazınızı onaylamak için aşağıdaki bağlantıyı tarayıcınızda açın:\n\n  %s\n\n", resp.AuthURL)
		fmt.Println("Onaylandıktan sonra bağlantı otomatik olarak kurulacaktır.")
		return
	}

	fmt.Println("Başarılı:", resp.Status)
}

func cmdDown(ctx context.Context, client *localapi.Client, args []string) {
	if err := client.Down(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Hata: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("PeerLink bağlantısı kapatıldı.")
}

func cmdLogout(ctx context.Context, client *localapi.Client, args []string) {
	if err := client.Logout(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Hata: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Oturum kapatıldı, cihaz anahtarları sıfırlandı.")
}

func cmdIP(ctx context.Context, client *localapi.Client, args []string) {
	ip, err := client.IP(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Hata: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(ip)
}

func cmdStatus(ctx context.Context, client *localapi.Client, args []string) {
	st, err := client.Status(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Hata: %v\n", err)
		os.Exit(1)
	}

	if st.Self == nil {
		fmt.Printf("Durum: %s\n", st.BackendState)
		if st.AuthURL != "" {
			fmt.Printf("Giriş bekleniyor: %s\n", st.AuthURL)
		}
		return
	}

	selfIP := "-"
	if len(st.Self.Addresses) > 0 {
		selfIP = st.Self.Addresses[0].Addr().String()
	}

	fmt.Printf("%-18s %-16s %-10s %-12s\n", selfIP, st.Self.ShortName(), st.Self.Hostinfo.OS, "active; self")

	if len(st.Peers) == 0 {
		fmt.Println("\nAğda başka eş (peer) bulunmuyor.")
		return
	}

	fmt.Println()
	fmt.Printf("%-18s %-16s %-10s %-10s %-12s\n", "IP", "CİHAZ", "OS", "DURUM", "SON TRAFİK")
	for _, p := range st.Peers {
		status := "offline"
		if p.Online {
			status = "online"
		}
		if p.Active {
			status = "active; direct"
		}

		traffic := "-"
		if p.RxBytes > 0 || p.TxBytes > 0 {
			traffic = fmt.Sprintf("rx:%s tx:%s", formatBytes(p.RxBytes), formatBytes(p.TxBytes))
		}

		shortName := p.Name
		if i := strings.IndexByte(p.Name, '.'); i > 0 {
			shortName = p.Name[:i]
		}

		fmt.Printf("%-18s %-16s %-10s %-10s %-12s\n", p.IP, shortName, p.OS, status, traffic)
	}
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func cmdSSH(ctx context.Context, client *localapi.Client, args []string) {
	if len(args) < 1 {
		fmt.Println("Kullanım: peerlink ssh <kullanıcı@cihaz> [komut]")
		os.Exit(1)
	}

	target := args[0]
	remoteCmd := ""
	if len(args) > 1 {
		remoteCmd = strings.Join(args[1:], " ")
	}

	user, host, ok := strings.Cut(target, "@")
	if !ok {
		host = user
		user = os.Getenv("USER")
		if user == "" {
			user = "root"
		}
	}

	// Resolve target IP via local daemon status
	st, err := client.Status(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Hata: %v\n", err)
		os.Exit(1)
	}

	var targetIP string
	for _, p := range st.Peers {
		shortName := p.Name
		if i := strings.IndexByte(p.Name, '.'); i > 0 {
			shortName = p.Name[:i]
		}
		if shortName == host || p.Name == host || p.IP.String() == host {
			targetIP = p.IP.String()
			break
		}
	}

	if targetIP == "" {
		targetIP = host // try directly as IP or DNS
	}

	fmt.Printf("PeerLink SSH bağlanıyor -> %s@%s (%s)...\n", user, host, targetIP)

	sshArgs := []string{
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "LogLevel=ERROR",
		fmt.Sprintf("%s@%s", user, targetIP),
	}
	if remoteCmd != "" {
		sshArgs = append(sshArgs, remoteCmd)
	}

	cmd := exec.Command("ssh", sshArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		os.Exit(1)
	}
}

func cmdConfigure(args []string) {
	if len(args) < 1 || args[0] != "ssh" {
		fmt.Println("Kullanım: peerlink configure ssh")
		return
	}

	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Ev dizini bulunamadı: %v\n", err)
		return
	}

	sshDir := filepath.Join(home, ".ssh")
	_ = os.MkdirAll(sshDir, 0700)
	configPath := filepath.Join(sshDir, "config")

	snippet := `
# --- PeerLink SSH Başlangıç ---
Host *.peerlink
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    LogLevel ERROR
# --- PeerLink SSH Bitiş ---
`

	existing, _ := os.ReadFile(configPath)
	if strings.Contains(string(existing), "# --- PeerLink SSH Başlangıç ---") {
		fmt.Println("~/.ssh/config zaten PeerLink için yapılandırılmış.")
		return
	}

	f, err := os.OpenFile(configPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "~/.ssh/config açılamadı: %v\n", err)
		return
	}
	defer f.Close()

	if _, err := f.WriteString(snippet); err != nil {
		fmt.Fprintf(os.Stderr, "Yazma hatası: %v\n", err)
		return
	}

	fmt.Println("Başarılı! ~/.ssh/config güncellendi.")
	fmt.Println("Artık standart ssh komutunu kullanabilirsiniz:")
	fmt.Println("  ssh ubuntu@sunucu.peerlink")
}
