package fwtest

import (
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
)

// NewManagerFunc creates and initializes a firewall backend on the interface named ifaceName
// with the overlay address addr, and closes it when the test ends.
type NewManagerFunc func(t *testing.T, ifaceName string, addr wgaddr.Address) firewall.Manager

// RunTranslatedRoute routes a prefix that peers address onto the hosts' own prefix through
// the backend, with real packets. A peer namespace sits behind the NetBird interface and a
// second namespace holds a host of the routed network, so the host namespace forwards
// between them the way a routing peer forwards between the overlay and a site.
func RunTranslatedRoute(t *testing.T, newManager NewManagerFunc) {
	t.Helper()

	var (
		overlayHost = netip.MustParsePrefix("100.96.0.1/24")
		overlayPeer = netip.MustParsePrefix("100.96.0.2/24")
		lanHost     = netip.MustParsePrefix("192.168.77.1/24")
		lanPeer     = netip.MustParsePrefix("192.168.77.4/24")
		alias       = netip.MustParsePrefix("10.201.7.0/24")
		allowed     = netip.MustParseAddrPort("10.201.7.4:102")
		notAllowed  = netip.MustParseAddrPort("10.201.7.4:103")
	)

	overlay := NewPeerNamespace(t)
	lan := NewPeerNamespace(t)
	overlay.AddIPv4(t, overlayHost, overlayPeer)
	lan.AddIPv4(t, lanHost, lanPeer)
	overlay.AddPeerRoute(t, alias, overlayHost.Addr())

	remotes := lan.ListenPeer(t, netip.AddrPortFrom(lanPeer.Addr(), allowed.Port()))
	lan.ListenPeer(t, netip.AddrPortFrom(lanPeer.Addr(), notAllowed.Port()))

	fw := newManager(t, overlay.IfaceName, wgaddr.Address{IP: overlayHost.Addr(), Network: overlayHost.Masked()})
	require.NoError(t, fw.EnableRouting(), "enable routing")
	t.Cleanup(func() { assert.NoError(t, fw.DisableRouting(), "disable routing") })

	pair := firewall.RouterPair{
		ID:          "translated",
		Source:      firewall.Network{Prefix: netip.MustParsePrefix("0.0.0.0/0")},
		Destination: firewall.Network{Prefix: alias},
		Masquerade:  true,
		Translated:  lanPeer.Masked(),
	}
	require.NoError(t, fw.AddNatRule(pair), "add translated route")

	// The mapping lets the traffic past the external DNAT guard, but the route ACLs still
	// decide: with none, the connection must not reach the host.
	assert.Error(t, overlay.DialAddr(allowed), "translated traffic must be dropped without a route ACL")

	sources := []netip.Prefix{netip.PrefixFrom(overlayPeer.Addr(), 32)}
	_, err := fw.AddFilterRule(nil, sources, firewall.Network{Prefix: lanPeer.Masked()}, firewall.ProtocolTCP,
		nil, &firewall.Port{Values: []uint16{allowed.Port()}}, firewall.ActionAccept)
	require.NoError(t, err, "add route ACL on the translated prefix")
	require.NoError(t, fw.Flush(), "flush")

	require.Eventually(t, func() bool { return overlay.DialAddr(allowed) == nil }, 10*time.Second, 200*time.Millisecond,
		"a connection to the alias must reach the host at its own address")
	select {
	case remote := <-remotes:
		assert.Equal(t, lanHost.Addr(), remote.Addr(), "the host must see the routing peer, masqueraded, as the client")
	case <-time.After(5 * time.Second):
		t.Fatal("the host behind the translated prefix never accepted the connection")
	}

	assert.Error(t, overlay.DialAddr(notAllowed), "a port outside the route ACL must stay closed")

	require.NoError(t, fw.RemoveNatRule(pair), "remove translated route")
	assert.Error(t, overlay.DialAddr(allowed), "without the mapping the alias must lead nowhere")
}

// AddIPv4 assigns host to the host end and peer to the peer end, for tests that route IPv4
// through the host namespace.
func (ns *PeerNamespace) AddIPv4(t *testing.T, host, peer netip.Prefix) {
	t.Helper()

	require.NoError(t, addAddr(ns.IfaceName, host), "add %s to the host end", host)
	var err error
	ns.do(func() { err = addAddr(ns.peerName, peer) })
	require.NoError(t, err, "add %s to the peer end", peer)
}

// AddPeerRoute makes the namespace reach dst through the host end at via.
func (ns *PeerNamespace) AddPeerRoute(t *testing.T, dst netip.Prefix, via netip.Addr) {
	t.Helper()

	var err error
	ns.do(func() {
		link, lerr := netlink.LinkByName(ns.peerName)
		if lerr != nil {
			err = fmt.Errorf("find %s: %w", ns.peerName, lerr)
			return
		}
		err = netlink.RouteAdd(&netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       &net.IPNet{IP: dst.Addr().AsSlice(), Mask: net.CIDRMask(dst.Bits(), dst.Addr().BitLen())},
			Gw:        via.AsSlice(),
		})
	})
	require.NoError(t, err, "route %s via %s in the namespace", dst, via)
}

// ListenPeer starts a TCP listener at addr inside the namespace. Every connection it accepts
// is closed at once and its remote address sent on the returned channel, which drops what
// the test does not read.
func (ns *PeerNamespace) ListenPeer(t *testing.T, addr netip.AddrPort) <-chan netip.AddrPort {
	t.Helper()

	var ln net.Listener
	var err error
	// The socket keeps the namespace it was created in, so only the listen call has to run
	// there; accepting can happen on any thread.
	ns.do(func() { ln, err = net.Listen("tcp", addr.String()) })
	require.NoError(t, err, "listen on %s in the namespace", addr)
	t.Cleanup(func() { _ = ln.Close() })

	remotes := make(chan netip.AddrPort, 16)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if tcp, ok := c.RemoteAddr().(*net.TCPAddr); ok {
				remote := tcp.AddrPort()
				select {
				case remotes <- netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port()):
				default:
				}
			}
			_ = c.Close()
		}
	}()
	return remotes
}

// DialAddr opens a TCP connection to addr from inside the namespace and returns the dial
// error. Unlike Dial it takes either address family.
func (ns *PeerNamespace) DialAddr(addr netip.AddrPort) error {
	var err error
	ns.do(func() {
		d := net.Dialer{Timeout: time.Second}
		var conn net.Conn
		conn, err = d.Dial("tcp", addr.String())
		if err == nil {
			_ = conn.Close()
		}
	})
	return err
}

func addAddr(ifaceName string, prefix netip.Prefix) error {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return fmt.Errorf("find %s: %w", ifaceName, err)
	}
	ipNet := &net.IPNet{IP: prefix.Addr().AsSlice(), Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen())}
	if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: ipNet}); err != nil {
		return fmt.Errorf("add %s to %s: %w", prefix, ifaceName, err)
	}
	return nil
}
