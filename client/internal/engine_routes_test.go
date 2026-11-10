package internal

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/route"
	mgmtProto "github.com/netbirdio/netbird/shared/management/proto"
)

func TestToRoutes_TranslatedNetwork(t *testing.T) {
	protoRoutes := []*mgmtProto.Route{
		{
			ID:          "plain",
			NetID:       "plain",
			Network:     "10.0.0.0/24",
			NetworkType: int64(route.IPv4Network),
		},
		{
			ID:                "translated",
			NetID:             "translated",
			Network:           "10.201.7.0/24",
			NetworkType:       int64(route.IPv4Network),
			TranslatedNetwork: "192.168.77.9/24",
		},
		{
			// Served untranslated, this route would forward to whatever host
			// owns the alias on the routed network, so it is dropped instead.
			ID:                "unreadable",
			NetID:             "unreadable",
			Network:           "10.201.8.0/24",
			NetworkType:       int64(route.IPv4Network),
			TranslatedNetwork: "not-a-prefix",
		},
	}

	routes := toRoutes(protoRoutes)

	byID := make(map[route.ID]*route.Route, len(routes))
	for _, r := range routes {
		byID[r.ID] = r
	}

	require.Len(t, routes, 2, "only the route with an unreadable translation is skipped")

	require.Contains(t, byID, route.ID("plain"))
	assert.False(t, byID["plain"].TranslatedNetwork.IsValid(), "a route without a translation keeps the zero prefix")

	require.Contains(t, byID, route.ID("translated"))
	assert.Equal(t, netip.MustParsePrefix("10.201.7.0/24"), byID["translated"].Network, "peers route the address they use")
	assert.Equal(t, netip.MustParsePrefix("192.168.77.0/24"), byID["translated"].TranslatedNetwork, "the translation is read and masked")

	assert.NotContains(t, byID, route.ID("unreadable"), "a route whose translation cannot be read must not be served untranslated")
}
