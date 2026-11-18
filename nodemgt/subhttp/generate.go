package subhttp

import (
	"fmt"
	"strings"
	"time"

	"github.com/nuomiiiii/lite/nodemgt/models"
	"github.com/nuomiiiii/lite/nodemgt/store"
	"github.com/nuomiiiii/lite/nodemgt/sub"
	"github.com/nuomiiiii/lite/nodemgt/subtpl"
)

type GenerateRequest struct {
	Target    string
	Format    string
	UserAgent string
	// Only authenticated administrator preview handlers may set this override.
	Template *models.SubscriptionTemplate
}

// Generate is shared by public delivery and authenticated administrator previews.
func Generate(st *store.Store, row models.Subscription, req GenerateRequest) (subtpl.Document, error) {
	empty := subtpl.Document{}
	if !row.Enabled {
		return empty, store.ErrUserDisabled
	}
	user, err := st.GetUser(row.UserID)
	if err != nil {
		return empty, err
	}
	if user.Status != models.UserActive {
		return empty, store.ErrUserDisabled
	}
	if user.ExpiresAt != nil && !user.ExpiresAt.After(time.Now().UTC()) {
		_ = st.SetUserStatus(user.ID, models.UserExpired)
		return empty, store.ErrUserExpired
	}
	selection, err := subtpl.ResolveTarget(req.Target, req.Format, req.UserAgent, row.Format, row.AutoDetect)
	if err != nil {
		return empty, fmt.Errorf("%w: %v", store.ErrInvalid, err)
	}
	nodes, err := sub.ForUser(st, *user)
	if err != nil {
		return empty, err
	}
	extra := ExpandedExtras(st, row.UserID, row.ExtraURLs)
	explicitLegacyFormat := strings.TrimSpace(req.Format) != ""
	if req.Template == nil && (selection.Client == "v2ray" || explicitLegacyFormat) {
		format := selection.LegacyFormat
		if format == "" {
			format = "xray"
		}
		body, ctype, err := sub.Render(format, nodes, extra)
		return subtpl.Document{Body: body, ContentType: ctype, Client: selection.Client, Warnings: []string{}}, err
	}
	tpl := req.Template
	if tpl == nil {
		tpl, err = st.ResolveSubscriptionTemplate(row, selection.Client)
		if err != nil {
			return empty, err
		}
	}
	if tpl == nil && selection.LegacyFormat != "" {
		body, ctype, err := sub.Render(selection.LegacyFormat, nodes, extra)
		return subtpl.Document{Body: body, ContentType: ctype, Client: selection.Client, Warnings: []string{}}, err
	}
	kind := store.TemplateKindForClient(selection.Client)
	if tpl == nil {
		value := subtpl.DefaultTemplate(kind)
		tpl = &value
	}
	if tpl.Kind != kind {
		return empty, fmt.Errorf("%w: template kind does not match client", store.ErrInvalid)
	}
	return subtpl.Render(selection.Client, *tpl, nodes, extra)
}
