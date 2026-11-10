package manager

import (
	"fmt"
	"net/netip"

	"github.com/netbirdio/netbird/route"
)

type RouterPair struct {
	ID          route.ID
	Source      Network
	Destination Network
	Masquerade  bool
	Inverse     bool
	// Dynamic indicates the route is domain-based. NAT rules for dynamic
	// routes are duplicated to the v6 table so that resolved AAAA records
	// are masqueraded correctly.
	Dynamic bool
	// Translated is the prefix the Destination prefix is mapped onto, address
	// for address, before the traffic is forwarded. Zero when the destination
	// is forwarded as is.
	Translated netip.Prefix
}

// IsTranslated reports whether the pair maps its destination onto another prefix.
func (p RouterPair) IsTranslated() bool {
	return p.Translated.IsValid()
}

// ValidateTranslation checks that a translated pair maps a prefix onto another of
// the same family and length, the only shape an address for address mapping has.
func (p RouterPair) ValidateTranslation() error {
	if !p.IsTranslated() {
		return nil
	}
	if !p.Destination.IsPrefix() {
		return fmt.Errorf("translated destination %s is not a prefix", p.Destination)
	}
	dst := p.Destination.Prefix
	if dst.Addr().Is4() != p.Translated.Addr().Is4() {
		return fmt.Errorf("translate %s to %s: address families differ", dst, p.Translated)
	}
	if dst.Bits() != p.Translated.Bits() {
		return fmt.Errorf("translate %s to %s: prefix lengths differ", dst, p.Translated)
	}
	return nil
}

func GetInversePair(pair RouterPair) RouterPair {
	// The routed hosts answer and initiate from their own addresses, so the
	// return direction matches the translated prefix, not the one peers address.
	source := pair.Destination
	if pair.IsTranslated() {
		source = Network{Prefix: pair.Translated}
	}

	return RouterPair{
		ID: pair.ID,
		// invert Source/Destination
		Source:      source,
		Destination: pair.Source,
		Masquerade:  pair.Masquerade,
		Inverse:     true,
		Dynamic:     pair.Dynamic,
	}
}

// ToV6NatPair creates a v6 counterpart of a v4 NAT pair with `::/0` source
// and, for prefix destinations, `::/0` destination.
func ToV6NatPair(pair RouterPair) RouterPair {
	v6 := pair
	v6.Source = Network{Prefix: netip.PrefixFrom(netip.IPv6Unspecified(), 0)}
	if v6.Destination.IsPrefix() {
		v6.Destination = Network{Prefix: netip.PrefixFrom(netip.IPv6Unspecified(), 0)}
	}
	return v6
}
