package manager

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRouterPair_ValidateTranslation(t *testing.T) {
	tests := []struct {
		name        string
		destination Network
		translated  netip.Prefix
		expectErr   bool
	}{
		{
			name:        "untranslated prefix",
			destination: Network{Prefix: netip.MustParsePrefix("10.201.7.0/24")},
		},
		{
			name:        "untranslated domain set",
			destination: Network{Set: NewDomainSet(nil)},
		},
		{
			name:        "subnet onto subnet",
			destination: Network{Prefix: netip.MustParsePrefix("10.201.7.0/24")},
			translated:  netip.MustParsePrefix("192.168.77.0/24"),
		},
		{
			name:        "host onto host",
			destination: Network{Prefix: netip.MustParsePrefix("10.201.7.4/32")},
			translated:  netip.MustParsePrefix("192.168.77.4/32"),
		},
		{
			name:        "ipv6 subnet onto subnet",
			destination: Network{Prefix: netip.MustParsePrefix("fd00:1::/64")},
			translated:  netip.MustParsePrefix("fd00:2::/64"),
		},
		{
			name:        "domain set cannot be translated",
			destination: Network{Set: NewDomainSet(nil)},
			translated:  netip.MustParsePrefix("192.168.77.0/24"),
			expectErr:   true,
		},
		{
			name:        "prefix lengths differ",
			destination: Network{Prefix: netip.MustParsePrefix("10.201.7.0/24")},
			translated:  netip.MustParsePrefix("192.168.0.0/16"),
			expectErr:   true,
		},
		{
			name:        "address families differ",
			destination: Network{Prefix: netip.MustParsePrefix("10.201.7.0/24")},
			translated:  netip.MustParsePrefix("fd00:2::/24"),
			expectErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pair := RouterPair{
				ID:          "route1",
				Source:      Network{Prefix: netip.MustParsePrefix("0.0.0.0/0")},
				Destination: tt.destination,
				Translated:  tt.translated,
			}

			err := pair.ValidateTranslation()

			if tt.expectErr {
				assert.Error(t, err, "an address for address mapping needs two prefixes of one family and length")
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestGetInversePair(t *testing.T) {
	source := Network{Prefix: netip.MustParsePrefix("0.0.0.0/0")}
	alias := netip.MustParsePrefix("10.201.7.0/24")
	realPrefix := netip.MustParsePrefix("192.168.77.0/24")

	t.Run("untranslated", func(t *testing.T) {
		pair := RouterPair{
			ID:          "route1",
			Source:      source,
			Destination: Network{Prefix: alias},
			Masquerade:  true,
		}

		inverse := GetInversePair(pair)

		assert.Equal(t, pair.Destination, inverse.Source, "the inverse starts from the routed network")
		assert.Equal(t, pair.Source, inverse.Destination, "the inverse goes back to the sources")
		assert.True(t, inverse.Inverse, "the inverse must be marked as such")
		assert.Equal(t, pair.Masquerade, inverse.Masquerade, "masquerading applies to both directions")
	})

	t.Run("translated", func(t *testing.T) {
		pair := RouterPair{
			ID:          "route1",
			Source:      source,
			Destination: Network{Prefix: alias},
			Masquerade:  true,
			Translated:  realPrefix,
		}

		inverse := GetInversePair(pair)

		// Return traffic leaves the routed hosts from their own addresses, so
		// masquerading it has to match the translated prefix, not the alias.
		require.True(t, inverse.Source.IsPrefix(), "the inverse source must be a prefix")
		assert.Equal(t, realPrefix, inverse.Source.Prefix, "the inverse starts from the translated prefix")
		assert.Equal(t, pair.Source, inverse.Destination, "the inverse goes back to the sources")
		assert.False(t, inverse.IsTranslated(), "the inverse direction is not translated again")
	})
}

func TestRouterPair_TranslationKeysAreDistinct(t *testing.T) {
	pair := RouterPair{ID: "route1"}

	keys := map[RuleID]string{}
	for _, format := range []string{ForwardingFormat, PreroutingFormat, NatFormat, TranslationFormat, TranslationGuardFormat} {
		key := pair.GenKey(format)
		previous, exists := keys[key]
		assert.False(t, exists, "format %q yields the key of %q", format, previous)
		keys[key] = format
	}
}
