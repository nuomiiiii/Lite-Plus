package subhttp

import (
	"mime"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nuomiiiii/lite/nodemgt/models"
	"github.com/nuomiiiii/lite/nodemgt/store"
	"github.com/stretchr/testify/require"
)

func metadataFilename(t *testing.T, disposition string) string {
	t.Helper()
	mediaType, params, err := mime.ParseMediaType(disposition)
	require.NoError(t, err)
	require.Equal(t, "attachment", mediaType)
	require.NotContains(t, disposition, "\r")
	require.NotContains(t, disposition, "\n")
	for _, r := range disposition {
		require.Less(t, r, rune(128), "header must be ASCII, including Unicode filenames")
	}
	return params["filename"]
}

func metadataPlan(t *testing.T, st *store.Store, userID, name string, start time.Time, end *time.Time, created time.Time, shared bool) models.Plan {
	t.Helper()
	plan := models.Plan{Name: name, TrafficBytes: 200 << 30, SharedPool: shared}
	require.NoError(t, st.UpsertPlan(&plan))
	require.NoError(t, st.SaveAssignment(&models.Assignment{
		UserID: userID, PlanID: plan.ID, StartsAt: start, EndsAt: end,
		CreatedAt: created, OperationID: uuid.NewString(),
	}))
	return plan
}

func TestPublicSubscriptionMetadataAcrossFormats(t *testing.T) {
	st, row := subscriptionFixture(t)
	row.AutoDetect = true
	require.NoError(t, st.UpsertSubscription(&row))
	user, err := st.GetUser(row.UserID)
	require.NoError(t, err)
	now := time.Now().UTC()
	expires := now.Add(48 * time.Hour).Truncate(time.Second)
	user.Username, user.DisplayName = "MIKU", "not-the-username"
	user.QuotaBytes, user.UsedBytes, user.ExpiresAt = 100<<30, 1<<30, &expires
	require.NoError(t, st.UpsertUser(user))
	metadataPlan(t, st, user.ID, "月付 100GB", now.Add(-time.Hour), &expires, now, false)
	for _, tc := range []struct{ name, query, ua string }{
		{"automatic", "", "Clash-Verge/2.4"},
		{"fixed-fallback", "", "unknown-client"},
		{"mihomo", "?target=mihomo", ""},
		{"clash", "?target=clash", ""},
		{"loon", "?target=loon", ""},
		{"surge", "?target=surge", ""},
		{"surge-mac", "?target=surge-mac", ""},
		{"stash", "?target=stash", ""},
		{"sing-box", "?target=sing-box", ""},
		{"v2ray", "?target=v2ray", ""},
		{"legacy-clash", "?format=clash", ""},
		{"legacy-sing-box", "?format=sing-box", ""},
		{"legacy-base64", "?format=base64", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := publicSubscription(st, row.Token, tc.query, tc.ua)
			require.Equal(t, 200, w.Code, w.Body.String())
			require.Equal(t, "MIKU · 月付 100GB", metadataFilename(t, w.Header().Get("Content-Disposition")))
			require.Equal(t, "upload=0; download=1073741824; total=107374182400; expire="+strconv.FormatInt(expires.Unix(), 10), w.Header().Get("Subscription-Userinfo"))
		})
	}
}

func TestSubscriptionNameUsesNewestActiveExistingPlan(t *testing.T) {
	at := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	past, future := at.Add(-time.Hour), at.Add(time.Hour)
	for _, tc := range []struct {
		name, want string
		setup      func(*testing.T, *store.Store, string)
	}{
		{name: "no-plan", want: "alice"},
		{name: "active", want: "alice · Pro", setup: func(t *testing.T, st *store.Store, id string) {
			metadataPlan(t, st, id, "Pro", past, &future, past, false)
		}},
		{name: "permanent", want: "alice · Permanent", setup: func(t *testing.T, st *store.Store, id string) {
			metadataPlan(t, st, id, "Permanent", past, nil, past, false)
		}},
		{name: "starts-now", want: "alice · Pro", setup: func(t *testing.T, st *store.Store, id string) {
			metadataPlan(t, st, id, "Pro", at, &future, past, false)
		}},
		{name: "expires-now", want: "alice", setup: func(t *testing.T, st *store.Store, id string) {
			metadataPlan(t, st, id, "Expired", past, &at, past, false)
		}},
		{name: "future", want: "alice", setup: func(t *testing.T, st *store.Store, id string) {
			metadataPlan(t, st, id, "Future", future, nil, past, false)
		}},
		{name: "deleted-plan", want: "alice", setup: func(t *testing.T, st *store.Store, id string) {
			plan := metadataPlan(t, st, id, "Deleted", past, nil, past, false)
			require.NoError(t, st.DeletePlan(plan.ID))
		}},
		{name: "newest-eligible", want: "alice · New", setup: func(t *testing.T, st *store.Store, id string) {
			metadataPlan(t, st, id, "Old", past, &future, past, false)
			metadataPlan(t, st, id, "New", past, &future, past.Add(time.Minute), false)
			metadataPlan(t, st, id, "Expired", past, &at, past.Add(2*time.Minute), false)
			metadataPlan(t, st, id, "Future", future, nil, past.Add(3*time.Minute), false)
			deleted := metadataPlan(t, st, id, "Deleted", past, nil, past.Add(4*time.Minute), false)
			require.NoError(t, st.DeletePlan(deleted.ID))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, row := subscriptionFixture(t)
			if tc.setup != nil {
				tc.setup(t, st, row.UserID)
			}
			metadata, err := loadSubscriptionMetadata(st, row.UserID, at)
			require.NoError(t, err)
			require.Equal(t, tc.want, metadataFilename(t, metadata.contentDisposition))
		})
	}
}

func TestPublicSubscriptionMetadataSpecialQuotas(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		quota, used           int64
		permanent, sharedPlan bool
		poolID                string
		want                  string
	}{
		{name: "unlimited", used: 100, want: "upload=0; download=100; total=0"},
		{name: "negative-counters", quota: -1, used: -1, want: "upload=0; download=0; total=0"},
		{name: "permanent-finite", quota: 100, used: 20, permanent: true, want: "upload=0; download=20; total=100"},
		{name: "permanent-unlimited", permanent: true, want: "upload=0; download=0; total=0"},
		{name: "over-quota", quota: 100, used: 120, want: "upload=0; download=120; total=100"},
		{name: "shared-user", quota: 100, used: 20, poolID: "pool-1"},
		{name: "shared-plan", quota: 100, used: 20, sharedPlan: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, row := subscriptionFixture(t)
			user, err := st.GetUser(row.UserID)
			require.NoError(t, err)
			expires := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
			user.QuotaBytes, user.UsedBytes, user.SharedPoolID = tc.quota, tc.used, tc.poolID
			if !tc.permanent {
				user.ExpiresAt = &expires
			}
			require.NoError(t, st.UpsertUser(user))
			metadataPlan(t, st, user.ID, "Pro", time.Now().Add(-time.Hour), nil, time.Now(), tc.sharedPlan)
			w := publicSubscription(st, row.Token, "?target=mihomo", "")
			require.Equal(t, 200, w.Code, w.Body.String())
			require.Equal(t, "alice · Pro", metadataFilename(t, w.Header().Get("Content-Disposition")))
			want := tc.want
			if want != "" && !tc.permanent {
				want += "; expire=" + strconv.FormatInt(expires.Unix(), 10)
			}
			require.Equal(t, want, w.Header().Get("Subscription-Userinfo"))
			if tc.want == "" {
				require.NotContains(t, w.Header(), "Subscription-Userinfo")
			}
		})
	}
}

func TestSubscriptionMetadataRefreshesWithoutChangingBody(t *testing.T) {
	st, row := subscriptionFixture(t)
	before := publicSubscription(st, row.Token, "?target=mihomo", "")
	require.Equal(t, 200, before.Code)
	require.Equal(t, "alice", metadataFilename(t, before.Header().Get("Content-Disposition")))
	user, err := st.GetUser(row.UserID)
	require.NoError(t, err)
	user.DisplayName, user.QuotaBytes, user.UsedBytes = "ignored", 100, 30
	require.NoError(t, st.UpsertUser(user))
	plan := metadataPlan(t, st, user.ID, "New plan", time.Now().Add(-time.Hour), nil, time.Now(), false)
	after := publicSubscription(st, row.Token, "?target=mihomo", "")
	require.Equal(t, 200, after.Code)
	require.Equal(t, "alice · New plan", metadataFilename(t, after.Header().Get("Content-Disposition")))
	require.Equal(t, "upload=0; download=30; total=100", after.Header().Get("Subscription-Userinfo"))
	require.Equal(t, before.Body.String(), after.Body.String())
	user.Username = "new-user"
	require.NoError(t, st.UpsertUser(user))
	renamed := publicSubscription(st, row.Token, "?target=mihomo", "")
	require.Equal(t, 200, renamed.Code)
	require.Equal(t, "new-user · New plan", metadataFilename(t, renamed.Header().Get("Content-Disposition")))
	doc, err := Generate(st, row, GenerateRequest{Target: "mihomo"})
	require.NoError(t, err)
	require.Equal(t, doc.Body, renamed.Body.String())
	require.NoError(t, st.DeletePlan(plan.ID))
	withoutPlan := publicSubscription(st, row.Token, "?target=mihomo", "")
	require.Equal(t, "new-user", metadataFilename(t, withoutPlan.Header().Get("Content-Disposition")))
	stored, err := st.GetSubscriptionByToken(row.Token)
	require.NoError(t, err)
	require.Equal(t, row.ID, stored.ID)
}

func TestSubscriptionFilenameSanitizesUntrustedNames(t *testing.T) {
	st, row := subscriptionFixture(t)
	user, err := st.GetUser(row.UserID)
	require.NoError(t, err)
	user.Username = "米\r\n库/\\\""
	require.NoError(t, st.UpsertUser(user))
	metadataPlan(t, st, user.ID, "套餐\r\nX-Injected: yes/\\", time.Now().Add(-time.Hour), nil, time.Now(), false)
	w := publicSubscription(st, row.Token, "?target=mihomo", "")
	require.Equal(t, 200, w.Code)
	require.Equal(t, "米  库__\" · 套餐  X-Injected: yes__", metadataFilename(t, w.Header().Get("Content-Disposition")))
	require.Empty(t, w.Header().Get("X-Injected"))
}

func TestRejectedSubscriptionsOmitMetadata(t *testing.T) {
	for _, kind := range []string{"invalid-token", "disabled-subscription", "disabled-user", "expired-user", "metadata-error"} {
		t.Run(kind, func(t *testing.T) {
			st, row := subscriptionFixture(t)
			token := row.Token
			switch kind {
			case "invalid-token":
				token = "invalid"
			case "disabled-subscription":
				row.Enabled = false
				require.NoError(t, st.UpsertSubscription(&row))
			case "disabled-user":
				require.NoError(t, st.SetUserStatus(row.UserID, models.UserDisabled))
			case "expired-user":
				require.NoError(t, st.DB().Model(&models.NodeUser{}).Where("id = ?", row.UserID).Update("expires_at", time.Now().Add(-time.Minute)).Error)
			case "metadata-error":
				require.NoError(t, st.DB().Migrator().DropTable(&models.Assignment{}))
			}
			w := publicSubscription(st, token, "?target=v2ray", "")
			require.Equal(t, 404, w.Code)
			require.Empty(t, w.Header().Get("Content-Disposition"))
			require.Empty(t, w.Header().Get("Subscription-Userinfo"))
			require.NotContains(t, w.Body.String(), "alice")
		})
	}
}
