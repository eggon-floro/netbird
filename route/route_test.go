package route

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExpandV6ExitPairs(t *testing.T) {
	v4ExitRoute := &Route{Network: netip.MustParsePrefix("0.0.0.0/0")}
	v6ExitRoute := &Route{Network: netip.MustParsePrefix("::/0")}
	regularRoute := &Route{Network: netip.MustParsePrefix("10.0.0.0/8")}

	tests := []struct {
		name      string
		ids       []NetID
		routesMap map[NetID][]*Route
		expected  []NetID
	}{
		{
			name: "v4 exit node with matching v6 pair",
			ids:  []NetID{"exit-node"},
			routesMap: map[NetID][]*Route{
				"exit-node":    {v4ExitRoute},
				"exit-node-v6": {v6ExitRoute},
			},
			expected: []NetID{"exit-node", "exit-node-v6"},
		},
		{
			name: "v4 exit node without v6 pair",
			ids:  []NetID{"exit-node"},
			routesMap: map[NetID][]*Route{
				"exit-node": {v4ExitRoute},
			},
			expected: []NetID{"exit-node"},
		},
		{
			name: "regular route is not expanded",
			ids:  []NetID{"office"},
			routesMap: map[NetID][]*Route{
				"office":    {regularRoute},
				"office-v6": {v6ExitRoute},
			},
			expected: []NetID{"office"},
		},
		{
			name: "v6 already included is not duplicated",
			ids:  []NetID{"exit-node", "exit-node-v6"},
			routesMap: map[NetID][]*Route{
				"exit-node":    {v4ExitRoute},
				"exit-node-v6": {v6ExitRoute},
			},
			expected: []NetID{"exit-node", "exit-node-v6"},
		},
		{
			name: "multiple exit nodes expanded independently",
			ids:  []NetID{"exit-a", "exit-b"},
			routesMap: map[NetID][]*Route{
				"exit-a":    {v4ExitRoute},
				"exit-a-v6": {v6ExitRoute},
				"exit-b":    {v4ExitRoute},
				"exit-b-v6": {v6ExitRoute},
			},
			expected: []NetID{"exit-a", "exit-b", "exit-a-v6", "exit-b-v6"},
		},
		{
			name: "v6 suffix but not exit node network",
			ids:  []NetID{"office"},
			routesMap: map[NetID][]*Route{
				"office":    {regularRoute},
				"office-v6": {regularRoute},
			},
			expected: []NetID{"office"},
		},
		{
			name: "user-chosen name for exit node with v6 pair",
			ids:  []NetID{"my-exit"},
			routesMap: map[NetID][]*Route{
				"my-exit":    {v4ExitRoute},
				"my-exit-v6": {v6ExitRoute},
			},
			expected: []NetID{"my-exit", "my-exit-v6"},
		},
		{
			name: "real-world management-generated IDs",
			ids:  []NetID{"0.0.0.0/0"},
			routesMap: map[NetID][]*Route{
				"0.0.0.0/0":    {v4ExitRoute},
				"0.0.0.0/0-v6": {v6ExitRoute},
			},
			expected: []NetID{"0.0.0.0/0", "0.0.0.0/0-v6"},
		},
		{
			name:      "empty input",
			ids:       []NetID{},
			routesMap: map[NetID][]*Route{},
			expected:  []NetID{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExpandV6ExitPairs(tt.ids, tt.routesMap)
			assert.ElementsMatch(t, tt.expected, result)
		})
	}
}

func TestRoute_TranslatedNetworkCopiedAndCompared(t *testing.T) {
	r := &Route{
		ID:                "route1",
		Network:           netip.MustParsePrefix("10.201.7.0/24"),
		TranslatedNetwork: netip.MustParsePrefix("192.168.77.0/24"),
	}

	copied := r.Copy()
	assert.Equal(t, r.TranslatedNetwork, copied.TranslatedNetwork, "Copy must keep the translated network")
	assert.True(t, r.Equal(copied), "a route must equal its copy")

	// The route server replaces the firewall rules of a route only when the
	// route changed, so a new mapping must not compare equal to the old one.
	copied.TranslatedNetwork = netip.MustParsePrefix("192.168.88.0/24")
	assert.False(t, r.Equal(copied), "routes that map onto different prefixes must not be equal")
}
