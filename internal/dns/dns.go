// Package dns implements MagicDNS (embedded DNS server and OS resolver configuration)
// for PeerLink nodes.
package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/peerlink-go/peerlink/internal/types/proto"
)

// DNS record types
const (
	TypeA   = 1
	TypePTR = 12
)

// Server is an embedded DNS server.
type Server struct {
	domain    string
	listenIP  netip.Addr
	port      int
	upstreams []netip.Addr
	logf      func(format string, args ...any)

	mu      sync.RWMutex
	records map[string]netip.Addr // FQDN (lowercase, with trailing dot) -> IP
	ptr     map[string]string     // reverse IP -> FQDN
	udpConn *net.UDPConn
	closed  bool
}

// Config configures a MagicDNS Server.
type Config struct {
	Domain      string
	ListenIP    netip.Addr
	Port        int // default 53
	Nameservers []netip.Addr
	Logf        func(format string, args ...any)
}

// NewServer creates a new MagicDNS server.
func NewServer(cfg Config) *Server {
	if cfg.Port <= 0 {
		cfg.Port = 53
	}
	if cfg.Domain == "" {
		cfg.Domain = "peerlink"
	}
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}
	if len(cfg.Nameservers) == 0 {
		cfg.Nameservers = []netip.Addr{
			netip.MustParseAddr("1.1.1.1"),
			netip.MustParseAddr("8.8.8.8"),
		}
	}
	return &Server{
		domain:    strings.TrimSuffix(strings.ToLower(cfg.Domain), ".") + ".",
		listenIP:  cfg.ListenIP,
		port:      cfg.Port,
		upstreams: cfg.Nameservers,
		logf:      cfg.Logf,
		records:   make(map[string]netip.Addr),
		ptr:       make(map[string]string),
	}
}

// UpdateRecords updates the active peer name to IP mappings from NetMap.
func (s *Server) UpdateRecords(peers []proto.Node, self *proto.Node) {
	s.mu.Lock()
	defer s.mu.Unlock()

	newRecords := make(map[string]netip.Addr)
	newPTR := make(map[string]string)

	addNode := func(n *proto.Node) {
		if n == nil || len(n.Addresses) == 0 {
			return
		}
		ip := n.Addresses[0].Addr()
		fqdn := strings.TrimSuffix(strings.ToLower(n.Name), ".") + "."
		newRecords[fqdn] = ip

		// Also register short name e.g. "laptop." in our domain
		short := strings.ToLower(n.ShortName()) + "." + s.domain
		newRecords[short] = ip

		// Reverse PTR
		rev := fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", ip.As4()[3], ip.As4()[2], ip.As4()[1], ip.As4()[0])
		newPTR[rev] = fqdn
	}

	addNode(self)
	for i := range peers {
		addNode(&peers[i])
	}

	s.records = newRecords
	s.ptr = newPTR
}

// Start starts listening on UDP.
func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.listenIP.String(), s.port)
	if !s.listenIP.IsValid() {
		addr = fmt.Sprintf("0.0.0.0:%d", s.port)
	}

	uaddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", uaddr)
	if err != nil {
		return err
	}
	s.udpConn = conn
	go s.serveUDP()
	return nil
}

// Close stops the DNS server.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.udpConn != nil {
		return s.udpConn.Close()
	}
	return nil
}

func (s *Server) serveUDP() {
	buf := make([]byte, 1024)
	for {
		n, from, err := s.udpConn.ReadFromUDP(buf)
		if err != nil {
			return
		}

		query := make([]byte, n)
		copy(query, buf[:n])
		go s.handleQuery(query, from)
	}
}

func (s *Server) handleQuery(query []byte, from *net.UDPAddr) {
	resp := s.resolve(query)
	if resp != nil && s.udpConn != nil {
		_, _ = s.udpConn.WriteToUDP(resp, from)
	}
}

// ResolveForTest exposes resolution logic for tests.
func (s *Server) ResolveForTest(query []byte) []byte {
	return s.resolve(query)
}

// resolve resolves a DNS query or forwards to upstream.
func (s *Server) resolve(query []byte) []byte {
	if len(query) < 12 {
		return nil
	}

	qName, qType, err := parseQuestion(query)
	if err != nil {
		return nil
	}

	s.mu.RLock()
	ip, hasA := s.records[qName]
	ptrName, hasPTR := s.ptr[qName]
	s.mu.RUnlock()

	// 1. Handle MagicDNS A record
	if qType == TypeA && hasA {
		return buildAResponse(query, qName, ip)
	}

	// 2. Handle MagicDNS PTR record
	if qType == TypePTR && hasPTR {
		return buildPTRResponse(query, qName, ptrName)
	}

	// 3. If query belongs to our MagicDNS domain but not found: return NXDOMAIN
	if strings.HasSuffix(qName, s.domain) {
		return buildNXDomainResponse(query)
	}

	// 4. Forward to upstream recursive resolver
	return s.forwardUpstream(query)
}

func (s *Server) forwardUpstream(query []byte) []byte {
	if len(s.upstreams) == 0 {
		return buildNXDomainResponse(query)
	}

	upstream := s.upstreams[0]
	conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:53", upstream.String()), 2*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(query); err != nil {
		return nil
	}

	resp := make([]byte, 1024)
	n, err := conn.Read(resp)
	if err != nil {
		return nil
	}
	return resp[:n]
}

// ---- Wire DNS Helpers ----

func parseQuestion(query []byte) (qName string, qType uint16, err error) {
	pos := 12
	var labels []string
	for pos < len(query) {
		length := int(query[pos])
		if length == 0 {
			pos++
			break
		}
		pos++
		if pos+length > len(query) {
			return "", 0, errors.New("malformed question")
		}
		labels = append(labels, string(query[pos:pos+length]))
		pos += length
	}
	if pos+4 > len(query) {
		return "", 0, errors.New("truncated question")
	}
	qType = binary.BigEndian.Uint16(query[pos : pos+2])
	qName = strings.ToLower(strings.Join(labels, ".")) + "."
	return qName, qType, nil
}

func buildAResponse(query []byte, qName string, ip netip.Addr) []byte {
	resp := make([]byte, len(query)+16)
	copy(resp, query)

	// Flags: Standard query response, No error, Authoritative
	resp[2] = 0x81
	resp[3] = 0x80
	// Answer count = 1
	binary.BigEndian.PutUint16(resp[6:8], 1)

	// Answer RR: Pointer to question (0xc00c)
	pos := len(query)
	binary.BigEndian.PutUint16(resp[pos:pos+2], 0xc00c)
	binary.BigEndian.PutUint16(resp[pos+2:pos+4], TypeA)
	binary.BigEndian.PutUint16(resp[pos+4:pos+6], 1) // Class IN
	binary.BigEndian.PutUint32(resp[pos+6:pos+10], 60) // TTL 60s
	binary.BigEndian.PutUint16(resp[pos+10:pos+12], 4)  // Data length 4 bytes (IPv4)
	ip4 := ip.As4()
	copy(resp[pos+12:pos+16], ip4[:])

	return resp
}

func buildPTRResponse(query []byte, qName, targetFQDN string) []byte {
	labels := strings.Split(strings.TrimSuffix(targetFQDN, "."), ".")
	rdata := make([]byte, 0, len(targetFQDN)+2)
	for _, l := range labels {
		rdata = append(rdata, byte(len(l)))
		rdata = append(rdata, []byte(l)...)
	}
	rdata = append(rdata, 0)

	resp := make([]byte, len(query)+12+len(rdata))
	copy(resp, query)
	resp[2] = 0x81
	resp[3] = 0x80
	binary.BigEndian.PutUint16(resp[6:8], 1)

	pos := len(query)
	binary.BigEndian.PutUint16(resp[pos:pos+2], 0xc00c)
	binary.BigEndian.PutUint16(resp[pos+2:pos+4], TypePTR)
	binary.BigEndian.PutUint16(resp[pos+4:pos+6], 1)
	binary.BigEndian.PutUint32(resp[pos+6:pos+10], 60)
	binary.BigEndian.PutUint16(resp[pos+10:pos+12], uint16(len(rdata)))
	copy(resp[pos+12:], rdata)

	return resp
}

func buildNXDomainResponse(query []byte) []byte {
	resp := make([]byte, len(query))
	copy(resp, query)
	resp[2] = 0x81
	resp[3] = 0x83 // NXDOMAIN
	return resp
}

// ---- OS Resolver Configuration ----

// ConfigureOSResolver configures OS-level DNS routing for domain.
func ConfigureOSResolver(domain string, dnsIP netip.Addr, port int) error {
	switch runtime.GOOS {
	case "darwin":
		// On macOS: /etc/resolver/<domain>
		dir := "/etc/resolver"
		_ = os.MkdirAll(dir, 0755)
		content := fmt.Sprintf("nameserver %s\nport %d\n", dnsIP.String(), port)
		file := filepath.Join(dir, domain)
		return os.WriteFile(file, []byte(content), 0644)
	default:
		return nil
	}
}

// RemoveOSResolver cleans up OS resolver configuration on shutdown.
func RemoveOSResolver(domain string) error {
	switch runtime.GOOS {
	case "darwin":
		file := filepath.Join("/etc/resolver", domain)
		_ = os.Remove(file)
		return nil
	default:
		return nil
	}
}
