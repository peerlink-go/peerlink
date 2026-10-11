package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/peerlink-go/peerlink/internal/controlauth"
	"github.com/peerlink-go/peerlink/internal/localapi"
	"github.com/peerlink-go/peerlink/internal/magicsock"
	"github.com/peerlink-go/peerlink/internal/relay"
	"github.com/peerlink-go/peerlink/internal/router"
	"github.com/peerlink-go/peerlink/internal/types/key"
	"github.com/peerlink-go/peerlink/internal/types/proto"
	"github.com/peerlink-go/peerlink/internal/wgengine"
)

// DaemonConfig is persisted across daemon restarts.
type DaemonConfig struct {
	PrivateKey        key.Private `json:"privateKey"`
	ControlURL        string      `json:"controlURL"`
	Hostname          string      `json:"hostname"`
	AuthKey           string      `json:"authKey,omitempty"`
	SSH               bool        `json:"ssh"`
	AdvertiseExitNode bool        `json:"advertiseExitNode"`
	ExitNode          string      `json:"exitNode,omitempty"`
	AdvertiseRoutes   []string    `json:"advertiseRoutes,omitempty"`
}

type Daemon struct {
	cfgFile    string
	cfg        DaemonConfig
	engine      *wgengine.Engine
	router      router.Router
	magicConn   *magicsock.Conn
	relayClient *relay.Client
	controlPub  key.Public
	tunName     string
	useSimTUN   bool

	mu           sync.RWMutex
	backendState string // "Stopped", "Starting", "NeedsLogin", "Running"
	authURL      string
	self         *proto.Node
	peers        []proto.Node
	mapCancel    context.CancelFunc
}

func main() {
	var (
		cfgPath    = flag.String("config", "", "Yapılandırma dosya yolu")
		sockPath   = flag.String("socket", "", "Local API soket yolu")
		controlURL = flag.String("control-url", "http://localhost:8080", "Koordinasyon sunucusu adresi")
		tunName    = flag.String("tun", "", "TUN arayüz adı (boş = otomatik)")
		useSimTUN  = flag.Bool("sim-tun", false, "Test için simüle edilmiş TUN cihazı kullan")
	)
	flag.Parse()

	if *cfgPath == "" {
		home, _ := os.UserHomeDir()
		*cfgPath = filepath.Join(home, ".peerlink", "peerlinkd.json")
	}
	if *sockPath == "" {
		home, _ := os.UserHomeDir()
		*sockPath = filepath.Join(home, ".peerlink", "peerlinkd.sock")
	}

	d, err := newDaemon(*cfgPath, *controlURL, *tunName, *useSimTUN)
	if err != nil {
		log.Fatalf("Daemon başlatılamadı: %v", err)
	}

	l, err := localapi.ListenUnix(*sockPath)
	if err != nil {
		log.Fatalf("Soket dinlenemedi (%s): %v", *sockPath, err)
	}
	defer l.Close()
	defer os.Remove(*sockPath)

	apiSrv := localapi.NewServer(d)
	httpSrv := &http.Server{Handler: apiSrv.Handler()}

	go func() {
		if err := httpSrv.Serve(l); err != nil && err != http.ErrServerClosed {
			log.Printf("Local API kapandı: %v", err)
		}
	}()

	log.Printf("PeerLink Daemon (peerlinkd) başlatıldı.")
	log.Printf("Soket: %s", *sockPath)
	log.Printf("Düğüm Public Key: %s", d.cfg.PrivateKey.Public())

	// Auto-connect if already configured
	if d.cfg.ControlURL != "" {
		go func() {
			_, _ = d.Up(localapi.UpRequest{
				ControlURL:        d.cfg.ControlURL,
				AuthKey:           d.cfg.AuthKey,
				Hostname:          d.cfg.Hostname,
				SSH:               d.cfg.SSH,
				AdvertiseExitNode: d.cfg.AdvertiseExitNode,
				ExitNode:          d.cfg.ExitNode,
			})
		}()
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Println("peerlinkd kapatılıyor...")
	d.Down()
	httpSrv.Close()
}

func newDaemon(cfgFile, defaultControlURL, tunName string, useSimTUN bool) (*Daemon, error) {
	d := &Daemon{
		cfgFile:      cfgFile,
		backendState: "Stopped",
		tunName:      tunName,
		useSimTUN:    useSimTUN,
	}

	if err := d.loadConfig(); err != nil {
		return nil, err
	}
	if d.cfg.ControlURL == "" {
		d.cfg.ControlURL = defaultControlURL
	}
	return d, nil
}

func (d *Daemon) loadConfig() error {
	_ = os.MkdirAll(filepath.Dir(d.cfgFile), 0700)
	b, err := os.ReadFile(d.cfgFile)
	if err == nil {
		if err := json.Unmarshal(b, &d.cfg); err == nil && !d.cfg.PrivateKey.IsZero() {
			return nil
		}
	}
	// Generate new private key
	d.cfg.PrivateKey = key.NewPrivate()
	host, _ := os.Hostname()
	d.cfg.Hostname = host
	return d.saveConfig()
}

func (d *Daemon) saveConfig() error {
	b, err := json.MarshalIndent(d.cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(d.cfgFile, b, 0600)
}

// ---- localapi.DaemonBackend Implementation ----

func (d *Daemon) Status() (*localapi.StatusResponse, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	res := &localapi.StatusResponse{
		BackendState: d.backendState,
		Self:         d.self,
		ControlURL:   d.cfg.ControlURL,
		AuthURL:      d.authURL,
	}

	// Fetch runtime wgengine status if running
	var wgStats map[key.Public]wgengine.PeerStatus
	if d.engine != nil {
		if stList, err := d.engine.Status(); err == nil {
			wgStats = make(map[key.Public]wgengine.PeerStatus, len(stList))
			for _, s := range stList {
				wgStats[s.PublicKey] = s
			}
		}
	}

	for _, p := range d.peers {
		item := localapi.PeerStatusItem{
			ID:         p.ID,
			Name:       p.Name,
			Online:     p.Online,
			AllowedIPs: p.AllowedIPs,
			OS:         p.Hostinfo.OS,
			IsExitNode: p.IsExitNode(),
			SSH:        p.Hostinfo.SSHEnabled,
		}
		if len(p.Addresses) > 0 {
			item.IP = p.Addresses[0].Addr()
		}
		if st, ok := wgStats[p.Key]; ok {
			item.Endpoint = st.Endpoint
			item.LastHandshake = st.LastHandshake
			item.RxBytes = st.RxBytes
			item.TxBytes = st.TxBytes
			item.Active = !st.LastHandshake.IsZero() && time.Since(st.LastHandshake) < 5*time.Minute
		}
		res.Peers = append(res.Peers, item)
	}

	return res, nil
}

func (d *Daemon) IP() (string, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.self == nil || len(d.self.Addresses) == 0 {
		return "", fmt.Errorf("henüz bir IP atanmadı")
	}
	return d.self.Addresses[0].Addr().String(), nil
}

func (d *Daemon) Down() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.mapCancel != nil {
		d.mapCancel()
		d.mapCancel = nil
	}
	if d.engine != nil {
		d.engine.Close()
		d.engine = nil
	}
	if d.router != nil {
		d.router.Close()
		d.router = nil
	}
	d.backendState = "Stopped"
	d.peers = nil
	return nil
}

func (d *Daemon) Logout() error {
	d.Down()
	// Clear authKey and send logout request to control server
	client := &http.Client{Timeout: 10 * time.Second}
	logoutReq := proto.RegisterRequest{
		Version: proto.ProtocolVersion,
		Logout:  true,
	}
	body, _ := json.Marshal(logoutReq)
	req, _ := http.NewRequest("POST", d.cfg.ControlURL+proto.PathRegister, bytes.NewReader(body))
	if signer, err := controlauth.NewSigner(d.cfg.PrivateKey, d.controlPub); err == nil {
		signer.Sign(req, body)
		client.Do(req)
	}
	d.cfg.AuthKey = ""
	d.cfg.PrivateKey = key.NewPrivate() // new identity
	d.saveConfig()
	return nil
}

func (d *Daemon) Up(req localapi.UpRequest) (*localapi.UpResponse, error) {
	d.mu.Lock()
	if req.ControlURL != "" {
		d.cfg.ControlURL = strings.TrimRight(req.ControlURL, "/")
	}
	if req.AuthKey != "" {
		d.cfg.AuthKey = req.AuthKey
	}
	if req.Hostname != "" {
		d.cfg.Hostname = req.Hostname
	}
	d.cfg.SSH = req.SSH
	d.cfg.AdvertiseExitNode = req.AdvertiseExitNode
	if req.ExitNode != "" {
		d.cfg.ExitNode = req.ExitNode
	}
	d.saveConfig()
	d.backendState = "Starting"
	d.mu.Unlock()

	// 1. Fetch Control Server public key
	pub, err := d.fetchControlKey()
	if err != nil {
		d.mu.Lock()
		d.backendState = "Stopped"
		d.mu.Unlock()
		return nil, fmt.Errorf("control sunucusuna ulaşılamadı: %w", err)
	}
	d.controlPub = pub

	// 2. Initialize WireGuard Engine & Router if not yet created
	if err := d.initEngine(); err != nil {
		d.mu.Lock()
		d.backendState = "Stopped"
		d.mu.Unlock()
		return nil, fmt.Errorf("WireGuard motoru başlatılamadı: %w", err)
	}

	// 3. Register with Control Server
	regResp, err := d.sendRegister()
	if err != nil {
		return nil, fmt.Errorf("cihaz kaydı başarısız: %w", err)
	}

	if regResp.AuthURL != "" && !regResp.Authorized {
		d.mu.Lock()
		d.backendState = "NeedsLogin"
		d.authURL = regResp.AuthURL
		d.mu.Unlock()
		return &localapi.UpResponse{
			AuthURL: regResp.AuthURL,
			Status:  "Lütfen tarayıcıda bu adresi açarak cihazınızı onaylayın",
		}, nil
	}

	// 4. Start Map Streaming loop in background
	ctx, cancel := context.WithCancel(context.Background())
	d.mu.Lock()
	if d.mapCancel != nil {
		d.mapCancel()
	}
	d.mapCancel = cancel
	d.backendState = "Running"
	d.authURL = ""
	d.mu.Unlock()

	go d.runMapLoop(ctx)

	return &localapi.UpResponse{Status: "Bağlandı"}, nil
}

func (d *Daemon) fetchControlKey() (key.Public, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(d.cfg.ControlURL + proto.PathKey)
	if err != nil {
		return key.Public{}, err
	}
	defer resp.Body.Close()
	var kr proto.KeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&kr); err != nil {
		return key.Public{}, err
	}
	return kr.PublicKey, nil
}

func (d *Daemon) initEngine() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.engine != nil {
		return nil
	}

	var engConfig wgengine.Config
	engConfig.TunName = d.tunName
	if d.useSimTUN {
		engConfig.TunDevice = wgengine.NewSimTUN("peerlink-sim0", 1420)
	}

	magic := magicsock.New(magicsock.Config{NodeKey: d.cfg.PrivateKey})
	engConfig.Bind = magic

	eng, err := wgengine.New(engConfig)
	if err != nil {
		magic.Close()
		return err
	}
	if err := eng.SetPrivateKey(d.cfg.PrivateKey); err != nil {
		eng.Close()
		magic.Close()
		return err
	}

	rtr, err := router.New(router.Config{TunName: eng.TunName()})
	if err != nil {
		eng.Close()
		magic.Close()
		return err
	}

	d.engine = eng
	d.magicConn = magic
	d.router = rtr
	return nil
}

func (d *Daemon) sendRegister() (*proto.RegisterResponse, error) {
	var routableIPs []netip.Prefix
	if d.cfg.AdvertiseExitNode {
		routableIPs = append(routableIPs, netip.MustParsePrefix("0.0.0.0/0"))
	}
	for _, r := range d.cfg.AdvertiseRoutes {
		if pfx, err := netip.ParsePrefix(r); err == nil {
			routableIPs = append(routableIPs, pfx)
		}
	}

	regReq := proto.RegisterRequest{
		Version: proto.ProtocolVersion,
		AuthKey: d.cfg.AuthKey,
		Hostinfo: proto.Hostinfo{
			Hostname:    d.cfg.Hostname,
			OS:          runtime.GOOS,
			RoutableIPs: routableIPs,
			SSHEnabled:  d.cfg.SSH,
		},
	}

	body, _ := json.Marshal(regReq)
	req, err := http.NewRequest("POST", d.cfg.ControlURL+proto.PathRegister, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	signer, err := controlauth.NewSigner(d.cfg.PrivateKey, d.controlPub)
	if err != nil {
		return nil, err
	}
	signer.Sign(req, body)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var regResp proto.RegisterResponse
	if err := json.NewDecoder(resp.Body).Decode(&regResp); err != nil {
		return nil, err
	}
	if regResp.Error != "" {
		return nil, fmt.Errorf("%s", regResp.Error)
	}
	return &regResp, nil
}

func (d *Daemon) runMapLoop(ctx context.Context) {
	client := &http.Client{} // unbounded stream

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		mapReq := proto.MapRequest{
			Version:  proto.ProtocolVersion,
			DiscoKey: d.cfg.PrivateKey.Public(), // for now uses node key, magicsock will use discoKey
			Stream:   true,
		}

		mapBody, _ := json.Marshal(mapReq)
		req, err := http.NewRequestWithContext(ctx, "POST", d.cfg.ControlURL+proto.PathMap, bytes.NewReader(mapBody))
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}
		req.Header.Set("Content-Type", "application/json")

		signer, _ := controlauth.NewSigner(d.cfg.PrivateKey, d.controlPub)
		signer.Sign(req, mapBody)

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("Map akışı kesildi: %v (yeniden deneniyor)", err)
			time.Sleep(3 * time.Second)
			continue
		}

		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Bytes()
			if len(line) == 0 {
				continue
			}
			var mr proto.MapResponse
			if err := json.Unmarshal(line, &mr); err != nil {
				continue
			}
			if mr.KeepAlive {
				continue
			}

			d.handleMapUpdate(&mr)
		}
		resp.Body.Close()
		time.Sleep(1 * time.Second)
	}
}

func (d *Daemon) handleMapUpdate(mr *proto.MapResponse) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if mr.Node != nil {
		d.self = mr.Node
	}
	d.peers = mr.Peers

	if d.engine == nil || d.self == nil {
		return
	}

	// 1. Setup Relay Client if available
	if mr.RelayMap != nil && len(mr.RelayMap.Regions) > 0 && d.relayClient == nil {
		for _, region := range mr.RelayMap.Regions {
			if len(region.Nodes) > 0 {
				node := region.Nodes[0]
				rc, err := relay.NewClient(context.Background(), node.URL, d.cfg.PrivateKey.Public(), func(src key.Public, packet []byte) {
					if d.magicConn != nil {
						d.magicConn.ReceiveFromRelay(src, packet)
					}
				})
				if err == nil {
					d.relayClient = rc
					if d.magicConn != nil {
						d.magicConn.SetRelayClient(rc)
					}
					log.Printf("Relay sunucusuna bağlanıldı: %s", node.URL)
					break
				}
			}
		}
	}

	// 2. Update magicsock peer endpoints
	if d.magicConn != nil {
		for _, p := range mr.Peers {
			if len(p.Endpoints) > 0 {
				d.magicConn.SetPeerEndpoint(p.Key, p.Endpoints[0])
				// Trigger Disco NAT hole punch ping
				go d.magicConn.PingPeer(p.Key)
			}
		}
	}

	// 3. Update WireGuard Peers
	if err := d.engine.UpdateFromNetMap(d.self, mr.Peers); err != nil {
		log.Printf("WireGuard yapılandırma hatası: %v", err)
	}

	// 4. Update OS Routes via Router
	if d.router != nil && len(d.self.Addresses) > 0 {
		localIP := d.self.Addresses[0].Addr()
		var routes []netip.Prefix

		// Add entire CGNAT range (100.64.0.0/10) to TUN interface
		routes = append(routes, proto.CGNATRange)

		// If user selected an exit node, add 0.0.0.0/0
		if d.cfg.ExitNode != "" {
			routes = append(routes, netip.MustParsePrefix("0.0.0.0/0"))
		}

		if err := d.router.SetRoutes(localIP, routes); err != nil {
			log.Printf("Rota ayarlama hatası: %v", err)
		}
	}
}
