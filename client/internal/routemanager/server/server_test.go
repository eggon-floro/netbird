package server

import (
	"context"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/route"
)

// routingFirewall records the routing lifecycle calls the router makes. The
// embedded interface covers the methods this test never reaches.
type routingFirewall struct {
	firewall.Manager

	// rejectTranslated makes AddNatRule refuse translated pairs, as the
	// userspace firewall does.
	rejectTranslated bool

	added    []firewall.RouterPair
	removed  []firewall.RouterPair
	enabled  int
	disabled int
}

func (f *routingFirewall) AddNatRule(pair firewall.RouterPair) error {
	if f.rejectTranslated && pair.IsTranslated() {
		return firewall.ErrTranslationNotSupported
	}
	f.added = append(f.added, pair)
	return nil
}

func (f *routingFirewall) RemoveNatRule(pair firewall.RouterPair) error {
	f.removed = append(f.removed, pair)
	return nil
}

func (f *routingFirewall) EnableRouting() error {
	f.enabled++
	return nil
}

func (f *routingFirewall) DisableRouting() error {
	f.disabled++
	return nil
}

// TestRouterCleanUpReleasesRouting covers the shutdown path: the router holds a
// routing reference for as long as it serves routes, and CleanUp has to give it
// back. Without that the sysctls the reference enabled (IPv6 forwarding and the
// accept_ra values that keep RA handling working alongside it) stay applied
// after the client stops, leaving the host configured as a router.
func TestRouterCleanUpReleasesRouting(t *testing.T) {
	fw := &routingFirewall{}
	r := &Router{
		ctx:            context.Background(),
		firewall:       fw,
		statusRecorder: peer.NewRecorder("https://mgm"),
		routes: map[route.ID]*route.Route{
			"route-1": {
				ID:          "route-1",
				Network:     netip.MustParsePrefix("192.168.55.0/24"),
				NetworkType: route.IPv4Network,
				Masquerade:  true,
			},
		},
	}

	r.CleanUp()

	require.Len(t, fw.removed, 1, "the route's NAT rule must be removed")
	assert.Equal(t, 1, fw.disabled, "CleanUp must release the routing reference")
}

func newTestRouter(fw *routingFirewall) *Router {
	return &Router{
		ctx:            context.Background(),
		firewall:       fw,
		statusRecorder: peer.NewRecorder("https://mgm"),
		routes:         make(map[route.ID]*route.Route),
	}
}

func translatedRoute(translated string) *route.Route {
	return &route.Route{
		ID:                "route-1",
		Network:           netip.MustParsePrefix("10.201.7.0/24"),
		TranslatedNetwork: netip.MustParsePrefix(translated),
		NetworkType:       route.IPv4Network,
		Masquerade:        true,
	}
}

// TestRouterServesTranslatedRoute covers a route whose network peers address
// is mapped onto the hosts' own prefix: the firewall has to get both, the
// first as the destination it matches and the second as the one it maps to.
func TestRouterServesTranslatedRoute(t *testing.T) {
	fw := &routingFirewall{}
	r := newTestRouter(fw)

	err := r.UpdateRoutes(map[route.ID]*route.Route{"route-1": translatedRoute("192.168.77.0/24")}, false)
	require.NoError(t, err)

	require.Len(t, fw.added, 1, "the route's NAT rule must be added")
	pair := fw.added[0]
	assert.Equal(t, netip.MustParsePrefix("10.201.7.0/24"), pair.Destination.Prefix, "the firewall matches the address peers use")
	assert.Equal(t, netip.MustParsePrefix("192.168.77.0/24"), pair.Translated, "the firewall maps onto the hosts' own prefix")
	assert.Equal(t, 1, r.RoutesCount(), "the route must be recorded as served")
}

// TestRouterDoesNotServeRejectedTranslation covers a firewall that cannot
// translate. The route must not be recorded as served, so it is not reported
// as available and the next update tries it again.
func TestRouterDoesNotServeRejectedTranslation(t *testing.T) {
	fw := &routingFirewall{rejectTranslated: true}
	r := newTestRouter(fw)
	routes := map[route.ID]*route.Route{"route-1": translatedRoute("192.168.77.0/24")}

	require.NoError(t, r.UpdateRoutes(routes, false), "a refused route does not fail the whole update")
	assert.Empty(t, fw.added, "no NAT rule must be added for a refused translation")
	assert.Equal(t, 0, r.RoutesCount(), "a refused route must not be recorded as served")

	fw.rejectTranslated = false
	require.NoError(t, r.UpdateRoutes(routes, false))
	assert.Len(t, fw.added, 1, "the route is tried again on the next update")
	assert.Equal(t, 1, r.RoutesCount(), "the route is served once the firewall accepts it")
}

// TestRouterReplacesChangedTranslation covers a route that keeps its ID and
// network but maps onto another prefix. The rules of the old mapping must go
// before the new ones are added, or traffic keeps reaching the old hosts.
func TestRouterReplacesChangedTranslation(t *testing.T) {
	fw := &routingFirewall{}
	r := newTestRouter(fw)

	require.NoError(t, r.UpdateRoutes(map[route.ID]*route.Route{"route-1": translatedRoute("192.168.77.0/24")}, false))
	require.NoError(t, r.UpdateRoutes(map[route.ID]*route.Route{"route-1": translatedRoute("192.168.88.0/24")}, false))

	require.Len(t, fw.removed, 1, "the old mapping must be removed")
	assert.Equal(t, netip.MustParsePrefix("192.168.77.0/24"), fw.removed[0].Translated, "the removed pair is the old mapping")
	require.Len(t, fw.added, 2, "the new mapping must be added")
	assert.Equal(t, netip.MustParsePrefix("192.168.88.0/24"), fw.added[1].Translated, "the added pair is the new mapping")
	assert.Equal(t, 1, r.RoutesCount(), "the route stays served")
}
