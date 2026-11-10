package types

import (
	"net/netip"
	"testing"

	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

func TestGetResourceType(t *testing.T) {
	tests := []struct {
		input          string
		expectedType   NetworkResourceType
		expectedErr    bool
		expectedDomain string
		expectedPrefix netip.Prefix
	}{
		// Valid host IPs
		{"1.1.1.1", Host, false, "", netip.MustParsePrefix("1.1.1.1/32")},
		{"1.1.1.1/32", Host, false, "", netip.MustParsePrefix("1.1.1.1/32")},
		// Valid subnets
		{"192.168.1.0/24", Subnet, false, "", netip.MustParsePrefix("192.168.1.0/24")},
		{"10.0.0.0/16", Subnet, false, "", netip.MustParsePrefix("10.0.0.0/16")},
		// Valid domains
		{"example.com", Domain, false, "example.com", netip.Prefix{}},
		{"*.example.com", Domain, false, "*.example.com", netip.Prefix{}},
		{"sub.example.com", Domain, false, "sub.example.com", netip.Prefix{}},
		{"example.x", Domain, false, "example.x", netip.Prefix{}},
		{"internal", Domain, false, "internal", netip.Prefix{}},
		// Invalid inputs
		{"1.1.1.1/abc", "", true, "", netip.Prefix{}},
		{"-invalid.com", "", true, "", netip.Prefix{}},
		{"", "", true, "", netip.Prefix{}},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, domain, prefix, err := GetResourceType(tt.input)

			if result != tt.expectedType {
				t.Errorf("Expected type %v, got %v", tt.expectedType, result)
			}

			if tt.expectedErr && err == nil {
				t.Errorf("Expected error, got nil")
			}

			if prefix != tt.expectedPrefix {
				t.Errorf("Expected address %v, got %v", tt.expectedPrefix, prefix)
			}

			if domain != tt.expectedDomain {
				t.Errorf("Expected domain %v, got %v", tt.expectedDomain, domain)
			}
		})
	}
}

func TestNetworkResource_ApplyTranslatedAddress(t *testing.T) {
	tests := []struct {
		name       string
		address    string
		translated string
		expected   netip.Prefix
		expectErr  bool
	}{
		{name: "no translation", address: "10.201.7.0/24"},
		{name: "subnet", address: "10.201.7.0/24", translated: "192.168.77.0/24", expected: netip.MustParsePrefix("192.168.77.0/24")},
		{name: "subnet with host bits is masked", address: "10.201.7.0/24", translated: "192.168.77.9/24", expected: netip.MustParsePrefix("192.168.77.0/24")},
		{name: "host as prefix", address: "10.201.7.4/32", translated: "192.168.77.4/32", expected: netip.MustParsePrefix("192.168.77.4/32")},
		{name: "host as bare address", address: "10.201.7.4", translated: "192.168.77.4", expected: netip.MustParsePrefix("192.168.77.4/32")},
		{name: "ipv6 subnet", address: "fd00:1::/64", translated: "fd00:2::/64", expected: netip.MustParsePrefix("fd00:2::/64")},
		{name: "domain resource", address: "example.com", translated: "192.168.77.4", expectErr: true},
		{name: "prefix length differs", address: "10.201.7.0/24", translated: "192.168.0.0/16", expectErr: true},
		{name: "host onto subnet", address: "10.201.7.4", translated: "192.168.77.0/24", expectErr: true},
		{name: "ip version differs", address: "10.201.7.0/24", translated: "fd00:2::/24", expectErr: true},
		{name: "same as address", address: "10.201.7.0/24", translated: "10.201.7.0/24", expectErr: true},
		{name: "not an address", address: "10.201.7.0/24", translated: "example.com", expectErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resourceType, domain, prefix, err := GetResourceType(tt.address)
			if err != nil {
				t.Fatalf("resource address must parse: %v", err)
			}
			resource := &NetworkResource{
				Type:              resourceType,
				Domain:            domain,
				Prefix:            prefix,
				TranslatedAddress: tt.translated,
				// A stale value must not survive a failed or cleared translation.
				TranslatedPrefix: netip.MustParsePrefix("203.0.113.0/24"),
			}

			err = resource.ApplyTranslatedAddress()

			if tt.expectErr && err == nil {
				t.Errorf("Expected error, got nil")
			}
			if !tt.expectErr && err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
			if resource.TranslatedPrefix != tt.expected {
				t.Errorf("Expected translated prefix %v, got %v", tt.expected, resource.TranslatedPrefix)
			}
		})
	}
}

func TestNetworkResource_ToRouteCarriesTranslation(t *testing.T) {
	resource := &NetworkResource{
		ID:               "res1",
		Type:             Subnet,
		Prefix:           netip.MustParsePrefix("10.201.7.0/24"),
		TranslatedPrefix: netip.MustParsePrefix("192.168.77.0/24"),
	}

	r := resource.ToRoute(&nbpeer.Peer{ID: "peer1", Key: "key1"}, &routerTypes.NetworkRouter{})

	if r.Network != resource.Prefix {
		t.Errorf("Expected peers to route %v, got %v", resource.Prefix, r.Network)
	}
	if r.TranslatedNetwork != resource.TranslatedPrefix {
		t.Errorf("Expected translated network %v, got %v", resource.TranslatedPrefix, r.TranslatedNetwork)
	}
}
