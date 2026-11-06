package jsonrpc

import (
	"context"
	"fmt"
	"strings"

	"github.com/nuomiiiii/lite/nodemgt/models"
	"github.com/nuomiiiii/lite/nodemgt/store"
	"github.com/nuomiiiii/lite/nodemgt/subhttp"
	"github.com/nuomiiiii/lite/nodemgt/subtpl"
	"github.com/nuomiiiii/lite/pkg/rpc"
)

func init() {
	reg("nodemgt.template.list", nodemgtTemplateList, "List subscription templates and client bindings")
	reg("nodemgt.template.upsert", nodemgtTemplateUpsert, "Create or update a subscription template")
	reg("nodemgt.template.delete", nodemgtTemplateDelete, "Delete an unbound subscription template")
	reg("nodemgt.template.bind", nodemgtTemplateBind, "Set or clear a client template binding")
	reg("nodemgt.template.preview", nodemgtTemplatePreview, "Preview an unsaved template using an authorized user's nodes")
}

func nodemgtTemplateList(_ context.Context, _ *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	st := nodemgtST()
	rows, err := st.ListSubscriptionTemplates()
	if err != nil {
		return nil, nodemgtErr(err)
	}
	bindings, err := st.ListSubscriptionTemplateBindings()
	if err != nil {
		return nil, nodemgtErr(err)
	}
	return map[string]any{"templates": rows, "builtins": subtpl.BuiltinTemplates(), "bindings": bindings}, nil
}

func nodemgtTemplateUpsert(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var row models.SubscriptionTemplate
	if err := req.BindParams(&row); err != nil {
		return nil, rpc.MakeError(rpc.InvalidParams, err.Error(), nil)
	}
	content, err := subtpl.Prepare(row.Kind, row.Content)
	if err != nil {
		return nil, rpc.MakeError(rpc.InvalidParams, err.Error(), nil)
	}
	row.Content = content
	st := nodemgtST()
	if err := st.UpsertSubscriptionTemplate(&row); err != nil {
		return nil, nodemgtErr(err)
	}
	_ = nodemgtAudit(ctx, st, "nodemgt.template.upsert", row.ID, row.Name)
	return row, nil
}

func nodemgtTemplateDelete(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var p struct {
		ID string `json:"id"`
	}
	if err := req.BindParams(&p); err != nil {
		return nil, rpc.MakeError(rpc.InvalidParams, err.Error(), nil)
	}
	st := nodemgtST()
	name := p.ID
	if row, err := st.GetSubscriptionTemplate(p.ID); err == nil && row != nil && strings.TrimSpace(row.Name) != "" {
		name = row.Name
	}
	if err := st.DeleteSubscriptionTemplate(p.ID); err != nil {
		return nil, nodemgtErr(err)
	}
	_ = nodemgtAudit(ctx, st, "nodemgt.template.delete", p.ID, name)
	return map[string]any{"ok": true}, nil
}

func nodemgtTemplateBind(ctx context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var row models.SubscriptionTemplateBinding
	if err := req.BindParams(&row); err != nil {
		return nil, rpc.MakeError(rpc.InvalidParams, err.Error(), nil)
	}
	client, err := subtpl.NormalizeClient(row.Client)
	if err != nil {
		return nil, rpc.MakeError(rpc.InvalidParams, err.Error(), nil)
	}
	row.Client = client
	st := nodemgtST()
	if err := st.SetSubscriptionTemplateBinding(&row); err != nil {
		return nil, nodemgtErr(err)
	}
	_ = nodemgtAudit(ctx, st, "nodemgt.template.bind", row.ScopeID, fmt.Sprintf("%s/%s", row.Scope, row.Client))
	return map[string]any{"ok": true}, nil
}

func nodemgtTemplatePreview(_ context.Context, req *rpc.JsonRpcRequest) (any, *rpc.JsonRpcError) {
	var p struct {
		SubscriptionID string                      `json:"subscription_id"`
		Target         string                      `json:"target"`
		Template       models.SubscriptionTemplate `json:"template"`
	}
	if err := req.BindParams(&p); err != nil {
		return nil, rpc.MakeError(rpc.InvalidParams, err.Error(), nil)
	}
	st := nodemgtST()
	var row models.Subscription
	if err := st.DB().First(&row, "id = ?", p.SubscriptionID).Error; err != nil {
		return nil, nodemgtErr(store.ErrNotFound)
	}
	doc, err := subhttp.Generate(st, row, subhttp.GenerateRequest{Target: p.Target, Template: &p.Template})
	if err != nil {
		return nil, nodemgtErr(err)
	}
	return doc, nil
}
