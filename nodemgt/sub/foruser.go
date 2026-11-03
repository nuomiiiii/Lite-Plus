package sub

import (
	"strings"

	dbmodels "github.com/nuomiiiii/lite/database/models"
	"github.com/nuomiiiii/lite/nodemgt/models"
	"github.com/nuomiiiii/lite/nodemgt/store"
)

func ForUser(st *store.Store, user models.NodeUser) ([]Node, error) {
	if strings.EqualFold(strings.TrimSpace(user.Kind), models.UserKindRelay) {
		return nil, nil
	}
	grants, err := st.ListGrants(user.ID)
	if err != nil {
		return nil, err
	}
	granted := make(map[string]bool, len(grants))
	for _, g := range grants {
		granted[g.InboundID] = true
	}
	inbounds, err := st.ListInbounds("")
	if err != nil {
		return nil, err
	}
	creds, err := st.ListCredentials(user.ID)
	if err != nil {
		return nil, err
	}
	certs, err := st.ListCerts("")
	if err != nil {
		return nil, err
	}
	return assembleWithAddrs(user, inbounds, creds, granted, nodeShareAddrs(st, inbounds, granted), certs), nil
}

func nodeShareAddrs(st *store.Store, inbounds []models.Inbound, granted map[string]bool) map[string]nodeAddr {
	hosts := map[string]nodeAddr{}
	for _, in := range inbounds {
		if granted != nil && !granted[in.ID] {
			continue
		}
		if _, ok := hosts[in.NodeUUID]; ok {
			continue
		}
		var client dbmodels.Client
		if err := st.DB().Select("ipv4", "ipv6").Where("uuid = ?", in.NodeUUID).First(&client).Error; err != nil {
			continue
		}
		addrs := nodeAddr{
			IPv4: strings.TrimSpace(client.IPv4),
			IPv6: strings.TrimSpace(client.IPv6),
		}
		if addrs.IPv4 != "" || addrs.IPv6 != "" {
			hosts[in.NodeUUID] = addrs
		}
	}
	return hosts
}
