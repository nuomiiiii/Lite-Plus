package subhttp

import (
	"encoding/base64"
	"errors"
	"fmt"
	"mime"
	"strings"
	"time"
	"unicode"

	"github.com/nuomiiiii/lite/nodemgt/models"
	"github.com/nuomiiiii/lite/nodemgt/store"
)

const (
	SettingPublishName     = "sub_publish_name"
	SettingPublishUserinfo = "sub_publish_userinfo"
)

type subscriptionMetadata struct {
	contentDisposition string
	profileTitle       string
	userInfo           string
}

func MetadataPublishFlags(st *store.Store) (publishName, publishUserinfo bool) {
	if st == nil {
		return false, false
	}
	nameRaw, _ := st.GetSetting(SettingPublishName)
	infoRaw, _ := st.GetSetting(SettingPublishUserinfo)
	return settingOn(nameRaw), settingOn(infoRaw)
}

func loadSubscriptionMetadata(st *store.Store, userID string, at time.Time) (subscriptionMetadata, error) {
	empty := subscriptionMetadata{}
	user, err := st.GetUser(userID)
	if err != nil {
		return empty, err
	}
	if user.Status != models.UserActive {
		return empty, nil
	}
	if user.ExpiresAt != nil && !user.ExpiresAt.After(at) {
		return empty, nil
	}
	plan, err := activeSubscriptionPlan(st, userID, at)
	if err != nil {
		return empty, err
	}
	name := subscriptionNamePart(user.Username)
	if plan != nil {
		if planName := subscriptionNamePart(plan.Name); planName != "" {
			name += " · " + planName
		}
	}
	metadata := subscriptionMetadata{}
	if name != "" {
		// FormatMediaType uses RFC 2231 filename* encoding for Unicode names.
		metadata.contentDisposition = mime.FormatMediaType("attachment", map[string]string{"filename": name})
		metadata.profileTitle = "base64:" + base64.StdEncoding.EncodeToString([]byte(name))
	}
	// Shared-pool accounting is not implemented yet. Per-user counters cannot
	// describe a pool, so omit quota metadata instead of advertising false totals.
	if strings.TrimSpace(user.SharedPoolID) != "" || (plan != nil && plan.SharedPool) {
		return metadata, nil
	}
	// Only aggregate usage is stored. The split is a compatibility mapping, not
	// a claim that all traffic was downloaded. Zero total means no finite quota.
	metadata.userInfo = fmt.Sprintf("upload=0; download=%d; total=%d", max(user.UsedBytes, 0), max(user.QuotaBytes, 0))
	if user.ExpiresAt != nil {
		metadata.userInfo += fmt.Sprintf("; expire=%d", user.ExpiresAt.Unix())
	}
	return metadata, nil
}

func activeSubscriptionPlan(st *store.Store, userID string, at time.Time) (*models.Plan, error) {
	assignments, err := st.ListAssignments(userID)
	if err != nil {
		return nil, err
	}
	// Assignments are newest first, matching subscription template precedence.
	for _, assignment := range assignments {
		if assignment.StartsAt.After(at) || (assignment.EndsAt != nil && !assignment.EndsAt.After(at)) {
			continue
		}
		plan, err := st.GetPlan(assignment.PlanID)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return plan, nil
	}
	return nil, nil
}

func subscriptionNamePart(value string) string {
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		switch {
		case unicode.IsControl(r):
			return ' '
		case r == '/' || r == '\\' || r == '"' || r == '<' || r == '>' || r == '|' || r == '*' || r == '?':
			return '_'
		default:
			return r
		}
	}, value))
}
