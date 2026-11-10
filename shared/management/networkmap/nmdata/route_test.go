package nmdata

import (
	"net/netip"
	"testing"
)

func TestRoute_ForwardedNetwork(t *testing.T) {
	alias := netip.MustParsePrefix("10.201.7.0/24")
	realPrefix := netip.MustParsePrefix("192.168.77.0/24")

	plain := &Route{Network: alias}
	if got := plain.ForwardedNetwork(); got != alias {
		t.Errorf("an untranslated route forwards to its own network %s, got %s", alias, got)
	}

	// The routing peer filters after the translation, so its rules have to
	// name the hosts' own prefix rather than the one peers address.
	translated := &Route{Network: alias, TranslatedNetwork: realPrefix}
	if got := translated.ForwardedNetwork(); got != realPrefix {
		t.Errorf("a translated route forwards to %s, got %s", realPrefix, got)
	}
}

func TestRoute_TranslatedNetworkCopiedAndCompared(t *testing.T) {
	r := &Route{
		ID:                "route1",
		Network:           netip.MustParsePrefix("10.201.7.0/24"),
		TranslatedNetwork: netip.MustParsePrefix("192.168.77.0/24"),
	}

	copied := r.Copy()
	if copied.TranslatedNetwork != r.TranslatedNetwork {
		t.Errorf("Copy must keep the translated network %s, got %s", r.TranslatedNetwork, copied.TranslatedNetwork)
	}
	if !r.Equal(copied) {
		t.Errorf("a route must equal its copy")
	}

	// A route that maps onto another prefix reaches other hosts, so the
	// change must not be mistaken for no change.
	copied.TranslatedNetwork = netip.MustParsePrefix("192.168.88.0/24")
	if r.Equal(copied) {
		t.Errorf("routes that map onto different prefixes must not be equal")
	}
}
