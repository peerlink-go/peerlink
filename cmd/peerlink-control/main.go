package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/peerlink-go/peerlink/internal/control"
	"github.com/peerlink-go/peerlink/internal/control/store"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	subcmd := os.Args[1]
	switch subcmd {
	case "serve":
		cmdServe(os.Args[2:])
	case "create-user":
		cmdCreateUser(os.Args[2:])
	case "create-auth-key":
		cmdCreateAuthKey(os.Args[2:])
	case "list-nodes":
		cmdListNodes(os.Args[2:])
	case "list-users":
		cmdListUsers(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "Bilinmeyen komut: %s\n\n", subcmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Print(`PeerLink Koordinasyon Sunucusu (peerlink-control)

Kullanım:
  peerlink-control <komut> [seçenekler]

Komutlar:
  serve             Koordinasyon ve admin sunucusunu başlatır
  create-user       Yeni kullanıcı oluşturur
  create-auth-key   Cihaz kaydı için auth-key üretir
  list-nodes        Kayıtlı düğümleri listeler
  list-users        Kullanıcıları listeler
`)
}

func defaultDBPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".peerlink", "control.db")
}

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	listenAddr := fs.String("listen", ":8080", "Dinlenecek HTTP adresi (host:port)")
	dbPath := fs.String("db", defaultDBPath(), "SQLite veritabanı dosya yolu")
	serverURL := fs.String("url", "http://localhost:8080", "Dışarıdan erişilebilir sunucu adresi")
	domain := fs.String("domain", "peerlink", "MagicDNS alan adı")
	reqApproval := fs.Bool("require-approval", false, "Yeni cihazlar için admin onayı zorunlu olsun")
	fs.Parse(args)

	_ = os.MkdirAll(filepath.Dir(*dbPath), 0700)
	st, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("Veritabanı açılamadı: %v", err)
	}
	defer st.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, err := control.New(ctx, control.Config{
		ServerURL:       *serverURL,
		Domain:          *domain,
		RequireApproval: *reqApproval,
	}, st)
	if err != nil {
		log.Fatalf("Control sunucusu başlatılamadı: %v", err)
	}

	go srv.Run(ctx)

	httpServer := &http.Server{
		Addr:         *listenAddr,
		Handler:      srv.Handler(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 0, // Streaming responses (Map) need unbounded write timeout
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Printf("PeerLink Control dinleniyor: %s (Sunucu Adresi: %s)", *listenAddr, *serverURL)
		log.Printf("Public Key: %s", srv.PublicKey())
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP sunucu hatası: %v", err)
		}
	}()

	<-sigCh
	log.Println("Kapatılıyor...")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	httpServer.Shutdown(shutdownCtx)
}

func cmdCreateUser(args []string) {
	fs := flag.NewFlagSet("create-user", flag.ExitOnError)
	dbPath := fs.String("db", defaultDBPath(), "SQLite veritabanı dosya yolu")
	email := fs.String("email", "", "Kullanıcı e-posta adresi")
	name := fs.String("name", "", "Görünen isim")
	password := fs.String("password", "", "Parola (en az 8 karakter)")
	role := fs.String("role", "member", "Rol: admin veya member")
	fs.Parse(args)

	if *email == "" || *password == "" {
		log.Fatal("Lütfen --email ve --password belirtin")
	}

	st, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("Veritabanı açılamadı: %v", err)
	}
	defer st.Close()

	u, err := st.CreateUser(context.Background(), *email, *name, *password, *role)
	if err != nil {
		log.Fatalf("Kullanıcı oluşturulamadı: %v", err)
	}
	fmt.Printf("Kullanıcı oluşturuldu: ID=%d, Email=%s, Rol=%s\n", u.ID, u.Email, u.Role)
}

func cmdCreateAuthKey(args []string) {
	fs := flag.NewFlagSet("create-auth-key", flag.ExitOnError)
	dbPath := fs.String("db", defaultDBPath(), "SQLite veritabanı dosya yolu")
	userID := fs.Int64("user", 1, "Kullanıcı ID")
	desc := fs.String("desc", "CLI generated", "Açıklama")
	reusable := fs.Bool("reusable", false, "Birden fazla kez kullanılabilir mi")
	ephemeral := fs.Bool("ephemeral", false, "Düğüm çevrimdışı olunca silinsin mi")
	preauth := fs.Bool("preauth", true, "Ön onaylı mı (admin onayı gerekmez)")
	expiryDays := fs.Int("days", 90, "Geçerlilik süresi (gün)")
	fs.Parse(args)

	st, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("Veritabanı açılamadı: %v", err)
	}
	defer st.Close()

	secret, key, err := st.CreateAuthKey(context.Background(), store.AuthKeyOptions{
		UserID:        *userID,
		Description:   *desc,
		Reusable:      *reusable,
		Ephemeral:     *ephemeral,
		Preauthorized: *preauth,
		Expiry:        time.Duration(*expiryDays) * 24 * time.Hour,
	})
	if err != nil {
		log.Fatalf("AuthKey oluşturulamadı: %v", err)
	}

	fmt.Printf("Auth Key başarıyla oluşturuldu!\n")
	fmt.Printf("Anahtar (yalnızca bir kez gösterilir): %s\n", secret)
	fmt.Printf("ID: %d | Ön Onaylı: %v | Tekrar Kullanılabilir: %v\n", key.ID, key.Preauthorized, key.Reusable)
}

func cmdListNodes(args []string) {
	fs := flag.NewFlagSet("list-nodes", flag.ExitOnError)
	dbPath := fs.String("db", defaultDBPath(), "SQLite veritabanı dosya yolu")
	fs.Parse(args)

	st, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("Veritabanı açılamadı: %v", err)
	}
	defer st.Close()

	nodes, err := st.ListNodes(context.Background(), 0)
	if err != nil {
		log.Fatalf("Düğümler listelenemedi: %v", err)
	}

	fmt.Printf("%-6s %-16s %-16s %-8s %-12s\n", "ID", "İSİM", "IP", "ONAYLI", "SON GÖRÜLME")
	for _, n := range nodes {
		lastSeen := "-"
		if !n.LastSeen.IsZero() {
			lastSeen = n.LastSeen.Format("15:04:05")
		}
		fmt.Printf("%-6d %-16s %-16s %-8v %-12s\n", n.ID, n.Name, n.IPv4, n.Authorized, lastSeen)
	}
}

func cmdListUsers(args []string) {
	fs := flag.NewFlagSet("list-users", flag.ExitOnError)
	dbPath := fs.String("db", defaultDBPath(), "SQLite veritabanı dosya yolu")
	fs.Parse(args)

	st, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("Veritabanı açılamadı: %v", err)
	}
	defer st.Close()

	users, err := st.ListUsers(context.Background())
	if err != nil {
		log.Fatalf("Kullanıcılar listelenemedi: %v", err)
	}

	fmt.Printf("%-6s %-25s %-15s %-10s\n", "ID", "EMAIL", "İSİM", "ROL")
	for _, u := range users {
		fmt.Printf("%-6d %-25s %-15s %-10s\n", u.ID, u.Email, u.DisplayName, u.Role)
	}
}
