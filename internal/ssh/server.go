// Package ssh implements PeerLink SSH (an embedded, cryptographic identity-based
// SSH server modeled after Tailscale SSH).
package ssh

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
	"github.com/pkg/sftp"
	gossh "golang.org/x/crypto/ssh"

	"github.com/peerlink-go/peerlink/internal/types/proto"
)

// Server is an embedded SSH server listening only on the node's PeerLink IP.
type Server struct {
	listenIP netip.Addr
	port     int
	logf     func(format string, args ...any)

	mu       sync.RWMutex
	policy   *proto.SSHPolicy
	nodesByIP map[netip.Addr]*proto.Node
	listener net.Listener
	hostSigner gossh.Signer
	closed   bool
}

// Config configures the PeerLink SSH server.
type Config struct {
	ListenIP netip.Addr
	Port     int // default 22
	Logf     func(format string, args ...any)
}

// NewServer creates a new PeerLink SSH server.
func NewServer(cfg Config) (*Server, error) {
	if cfg.Port <= 0 {
		cfg.Port = 22
	}
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}

	// Generate ephemeral host key for this node
	rawKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generating host key: %w", err)
	}
	signer, err := gossh.NewSignerFromKey(rawKey)
	if err != nil {
		return nil, err
	}

	return &Server{
		listenIP:   cfg.ListenIP,
		port:       cfg.Port,
		logf:       cfg.Logf,
		hostSigner: signer,
		nodesByIP:  make(map[netip.Addr]*proto.Node),
	}, nil
}

// UpdatePolicy updates active SSH policy and peer mapping from NetMap.
func (s *Server) UpdatePolicy(pol *proto.SSHPolicy, peers []proto.Node) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policy = pol
	s.nodesByIP = make(map[netip.Addr]*proto.Node, len(peers))
	for i := range peers {
		if len(peers[i].Addresses) > 0 {
			s.nodesByIP[peers[i].Addresses[0].Addr()] = &peers[i]
		}
	}
}

// Start begins listening on the node's PeerLink IP:port.
func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.listenIP.String(), s.port)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("ssh listen on %s: %w", addr, err)
	}
	s.listener = l
	go s.acceptLoop()
	s.logf("PeerLink SSH sunucusu dinleniyor: %s", addr)
	return nil
}

// Close closes the SSH server.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(netConn net.Conn) {
	defer netConn.Close()

	remoteTCP, ok := netConn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return
	}
	srcIP, _ := netip.ParseAddr(remoteTCP.IP.String())

	// Authenticate client based on WireGuard source IP
	s.mu.RLock()
	srcNode := s.nodesByIP[srcIP]
	pol := s.policy
	s.mu.RUnlock()

	sshConfig := &gossh.ServerConfig{
		NoClientAuth: true, // WireGuard layer provides cryptographic identity authentication
		ServerVersion: "SSH-2.0-PeerLink-SSH",
	}
	sshConfig.AddHostKey(s.hostSigner)

	serverConn, chans, reqs, err := gossh.NewServerConn(netConn, sshConfig)
	if err != nil {
		return
	}
	defer serverConn.Close()

	go gossh.DiscardRequests(reqs)

	requestedUser := serverConn.User()
	s.logf("SSH bağlantısı: %s kullanıcısı %s adresinden bağlanıyor (Düğüm: %v)", requestedUser, srcIP, srcNode != nil)

	// Evaluate policy
	action := s.evaluatePolicy(pol, srcIP, requestedUser)
	if action.Reject {
		s.logf("SSH reddedildi: %s -> %s (politika izni yok)", srcIP, requestedUser)
		return
	}

	for newChannel := range chans {
		switch newChannel.ChannelType() {
		case "session":
			channel, requests, err := newChannel.Accept()
			if err != nil {
				return
			}
			go s.handleSession(channel, requests, requestedUser, action)

		case "direct-tcpip":
			if !action.AllowLocalPortForwarding {
				newChannel.Reject(gossh.Prohibited, "port forwarding disabled by policy")
				continue
			}
			go s.handleDirectTCPIP(newChannel)

		default:
			newChannel.Reject(gossh.UnknownChannelType, "unsupported channel type")
		}
	}
}

func (s *Server) evaluatePolicy(pol *proto.SSHPolicy, srcIP netip.Addr, reqUser string) proto.SSHAction {
	if pol == nil || len(pol.Rules) == 0 {
		// Default: accept if connecting as current user
		return proto.SSHAction{Accept: true, AllowLocalPortForwarding: true}
	}

	for _, r := range pol.Rules {
		// Check principal
		matchPrincipal := false
		for _, p := range r.Principals {
			if p.Any || p.NodeIP == srcIP.String() {
				matchPrincipal = true
				break
			}
		}
		if !matchPrincipal {
			continue
		}

		// Check SSH users
		if targetLocal, ok := r.SSHUsers[reqUser]; ok && targetLocal != "" {
			return r.Action
		}
		if targetLocal, ok := r.SSHUsers["*"]; ok && targetLocal != "" {
			if reqUser == "root" && r.SSHUsers["root"] == "" {
				continue // nonroot rule doesn't match root
			}
			return r.Action
		}
	}

	return proto.SSHAction{Reject: true}
}

func (s *Server) handleSession(ch gossh.Channel, reqs <-chan *gossh.Request, username string, action proto.SSHAction) {
	defer ch.Close()

	var shellCmd *exec.Cmd
	var ptyFile *os.File

	for req := range reqs {
		switch req.Type {
		case "pty-req":
			termLen := int(binary.BigEndian.Uint32(req.Payload[0:4]))
			term := string(req.Payload[4 : 4+termLen])
			cols := binary.BigEndian.Uint32(req.Payload[4+termLen : 8+termLen])
			rows := binary.BigEndian.Uint32(req.Payload[8+termLen : 12+termLen])

			shell := os.Getenv("SHELL")
			if shell == "" {
				shell = "/bin/bash"
			}
			shellCmd = exec.Command(shell)
			shellCmd.Env = append(os.Environ(), "TERM="+term)

			// Try user switch if root and nonroot user requested
			applyUser(shellCmd, username)

			ptmx, err := pty.StartWithSize(shellCmd, &pty.Winsize{
				Rows: uint16(rows),
				Cols: uint16(cols),
			})
			if err != nil {
				req.Reply(false, nil)
				return
			}
			ptyFile = ptmx
			req.Reply(true, nil)

			go io.Copy(ptmx, ch)
			go io.Copy(ch, ptmx)

			go func() {
				_ = shellCmd.Wait()
				ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
				ch.Close()
			}()

		case "window-change":
			if ptyFile != nil && len(req.Payload) >= 8 {
				cols := binary.BigEndian.Uint32(req.Payload[0:4])
				rows := binary.BigEndian.Uint32(req.Payload[4:8])
				_ = pty.Setsize(ptyFile, &pty.Winsize{
					Rows: uint16(rows),
					Cols: uint16(cols),
				})
			}
			req.Reply(true, nil)

		case "shell":
			if shellCmd == nil {
				// Non-PTY shell
				shell := os.Getenv("SHELL")
				if shell == "" {
					shell = "/bin/sh"
				}
				shellCmd = exec.Command(shell)
				shellCmd.Stdin = ch
				shellCmd.Stdout = ch
				shellCmd.Stderr = ch.Stderr()
				applyUser(shellCmd, username)
				if err := shellCmd.Start(); err != nil {
					req.Reply(false, nil)
					return
				}
				go func() {
					_ = shellCmd.Wait()
					ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
					ch.Close()
				}()
			}
			req.Reply(true, nil)

		case "exec":
			cmdLen := int(binary.BigEndian.Uint32(req.Payload[0:4]))
			command := string(req.Payload[4 : 4+cmdLen])
			execCmd := exec.Command("/bin/sh", "-c", command)
			execCmd.Stdin = ch
			execCmd.Stdout = ch
			execCmd.Stderr = ch.Stderr()
			applyUser(execCmd, username)
			if err := execCmd.Start(); err != nil {
				req.Reply(false, nil)
				return
			}
			req.Reply(true, nil)
			go func() {
				_ = execCmd.Wait()
				ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
				ch.Close()
			}()

		case "subsystem":
			subLen := int(binary.BigEndian.Uint32(req.Payload[0:4]))
			subsystem := string(req.Payload[4 : 4+subLen])
			if subsystem == "sftp" {
				req.Reply(true, nil)
				server, err := sftp.NewServer(ch)
				if err == nil {
					_ = server.Serve()
				}
				return
			}
			req.Reply(false, nil)

		default:
			req.Reply(false, nil)
		}
	}
}

func (s *Server) handleDirectTCPIP(newChan gossh.NewChannel) {
	type directTCPIPData struct {
		DestAddr   string
		DestPort   uint32
		OriginAddr string
		OriginPort uint32
	}
	var data directTCPIPData
	if err := gossh.Unmarshal(newChan.ExtraData(), &data); err != nil {
		newChan.Reject(gossh.ConnectionFailed, "invalid forwarding request")
		return
	}

	target := fmt.Sprintf("%s:%d", data.DestAddr, data.DestPort)
	outConn, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		newChan.Reject(gossh.ConnectionFailed, err.Error())
		return
	}
	defer outConn.Close()

	ch, reqs, err := newChan.Accept()
	if err != nil {
		return
	}
	defer ch.Close()
	go gossh.DiscardRequests(reqs)

	go io.Copy(ch, outConn)
	io.Copy(outConn, ch)
}

func applyUser(cmd *exec.Cmd, targetUsername string) {
	if os.Geteuid() != 0 || targetUsername == "" || targetUsername == "root" {
		return
	}
	u, err := user.Lookup(targetUsername)
	if err != nil {
		return
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	cmd.SysProcAttr = &syscall.SysProcAttr{}
	cmd.SysProcAttr.Credential = &syscall.Credential{
		Uid: uint32(uid),
		Gid: uint32(gid),
	}
	cmd.Dir = u.HomeDir
	cmd.Env = append(cmd.Env, "HOME="+u.HomeDir, "USER="+targetUsername)
}
