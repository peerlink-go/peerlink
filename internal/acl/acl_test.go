package acl

import (
	"net/netip"
	"testing"
)

func node(id int64, ip string, uid int64, email string, tags ...string) *NodeInfo {
	return &NodeInfo{ID: id, IP: netip.MustParseAddr(ip), UserID: uid, UserEmail: email, Tags: tags}
}

func TestDefaultPolicyAllVisible(t *testing.T) {
	p := Default()
	a := node(1, "100.64.0.1", 1, "alice@x.com")
	b := node(2, "100.64.0.2", 2, "bob@x.com")
	c := node(3, "100.64.0.3", 1, "alice@x.com", "tag:server")
	all := []*NodeInfo{a, b, c}
	r := p.Compile(a, all, "")
	if len(r.Peers) != 2 {
		t.Fatalf("peers = %v, want 2", r.Peers)
	}
	if len(r.Filter) == 0 || r.Filter[0].SrcIPs[0] != "*" {
		t.Fatalf("filter = %+v", r.Filter)
	}
	// SSH default: alice can ssh to her own untagged devices only.
	if r.SSH == nil || len(r.SSH.Rules) != 1 {
		t.Fatalf("ssh = %+v", r.SSH)
	}
	if got := r.SSH.Rules[0].Principals; len(got) != 1 || got[0].NodeIP != "100.64.0.1" {
		t.Fatalf("principals = %+v", got)
	}
}

func TestGroupsAndTags(t *testing.T) {
	p, err := Parse([]byte(`{
		"groups": {"group:dev": ["alice@x.com"]},
		"tagOwners": {"tag:server": ["group:dev"]},
		"acls": [
			{"action": "accept", "src": ["group:dev"], "dst": ["tag:server:22,443"]},
		],
	}`))
	if err != nil {
		t.Fatal(err)
	}
	alice := node(1, "100.64.0.1", 1, "alice@x.com")
	bob := node(2, "100.64.0.2", 2, "bob@x.com")
	srv := node(3, "100.64.0.3", 1, "alice@x.com", "tag:server")
	all := []*NodeInfo{alice, bob, srv}

	if r := p.Compile(alice, all, ""); len(r.Peers) != 1 || r.Peers[3] == nil {
		t.Errorf("alice peers = %v, want only server", r.Peers)
	}
	if r := p.Compile(bob, all, ""); len(r.Peers) != 0 {
		t.Errorf("bob peers = %v, want none", r.Peers)
	}
	r := p.Compile(srv, all, "")
	if len(r.Peers) != 1 || r.Peers[1] == nil {
		t.Errorf("server peers = %v, want alice", r.Peers)
	}
	if len(r.Filter) != 1 || len(r.Filter[0].DstPorts) != 2 || r.Filter[0].SrcIPs[0] != "100.64.0.1" {
		t.Errorf("server filter = %+v", r.Filter)
	}
	if !p.CanOwnTag("alice@x.com", false, "tag:server") || p.CanOwnTag("bob@x.com", false, "tag:server") {
		t.Error("CanOwnTag wrong")
	}
}

func TestExitNode(t *testing.T) {
	p, _ := Parse([]byte(`{
		"acls": [{"action": "accept", "src": ["alice@x.com"], "dst": ["autogroup:internet:*"]}],
		"autoApprovers": {"exitNode": ["tag:exit"]},
	}`))
	alice := node(1, "100.64.0.1", 1, "alice@x.com")
	exit := node(2, "100.64.0.2", 1, "alice@x.com", "tag:exit")
	exit.Routes = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
	all := []*NodeInfo{alice, exit}

	r := p.Compile(alice, all, "")
	if !r.CanUseExitNodes || len(r.Peers[2]) != 2 {
		t.Fatalf("alice: %+v", r)
	}
	r = p.Compile(exit, all, "")
	if r.Peers[1] == nil || len(r.Filter) != 1 || r.Filter[0].DstPorts[0].IP != InternetDst {
		t.Fatalf("exit: %+v", r)
	}
	if !p.AutoApproved(exit, netip.MustParsePrefix("0.0.0.0/0")) {
		t.Error("exit node should be auto-approved")
	}
}

func TestSSHPolicy(t *testing.T) {
	p, err := Parse([]byte(`{
		"groups": {"group:ops": ["alice@x.com"]},
		"acls": [],
		"ssh": [
			{"action": "check", "src": ["group:ops"], "dst": ["tag:prod"], "users": ["root"], "checkPeriod": "1h"},
			{"action": "accept", "src": ["autogroup:member"], "dst": ["tag:prod"], "users": ["autogroup:nonroot"]},
		],
	}`))
	if err != nil {
		t.Fatal(err)
	}
	alice := node(1, "100.64.0.1", 1, "alice@x.com")
	bob := node(2, "100.64.0.2", 2, "bob@x.com")
	prod := node(3, "100.64.0.3", 1, "alice@x.com", "tag:prod")
	all := []*NodeInfo{alice, bob, prod}

	r := p.Compile(prod, all, "https://ctl/check")
	if r.SSH == nil || len(r.SSH.Rules) != 2 {
		t.Fatalf("ssh = %+v", r.SSH)
	}
	if r.SSH.Rules[0].Action.HoldAndDelegate != "https://ctl/check?period=1h0m0s" {
		t.Errorf("check url = %q", r.SSH.Rules[0].Action.HoldAndDelegate)
	}
	nr := r.SSH.Rules[1].SSHUsers
	if nr["*"] != "=" || nr["root"] != "" {
		t.Errorf("nonroot map = %v", nr)
	}
	if len(r.Peers) != 2 {
		t.Errorf("prod peers = %v (implicit ssh access)", r.Peers)
	}
	if r := p.Compile(bob, all, ""); r.Peers[3] == nil {
		t.Errorf("bob should see prod via ssh rule")
	}
}

func TestParseErrors(t *testing.T) {
	bad := []string{
		`{"acls": [{"action": "deny", "src": ["*"], "dst": ["*:*"]}]}`,
		`{"acls": [{"action": "accept", "src": ["group:nope"], "dst": ["*:*"]}]}`,
		`{"acls": [{"action": "accept", "src": ["*"], "dst": ["*"]}]}`,
		`{"acls": [{"action": "accept", "src": ["autogroup:self"], "dst": ["*:*"]}]}`,
		`{"acls": [{"action": "accept", "src": ["*"], "dst": ["*:99999"]}]}`,
		`{"unknown": 1, "acls": []}`,
	}
	for _, b := range bad {
		if _, err := Parse([]byte(b)); err == nil {
			t.Errorf("Parse(%s) succeeded, want error", b)
		}
	}
}
