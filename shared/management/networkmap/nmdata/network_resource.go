package nmdata

import "net/netip"

// NetworkResource is the slim twin of resources/types.NetworkResource.
type NetworkResource struct {
	ID          string
	NetworkID   string
	AccountID   string
	PublicID    string
	Name        string
	Description string
	Type        string
	Address     string // TODO: isn't persisted in the DB
	Domain      string
	Prefix      netip.Prefix
	// TranslatedPrefix is the prefix the routing peers map Prefix onto. Zero
	// when the resource is reached at Prefix itself.
	TranslatedPrefix netip.Prefix
	Enabled          bool
}
