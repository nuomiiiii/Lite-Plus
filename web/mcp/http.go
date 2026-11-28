package mcp

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nuomiiiii/lite/database/models"
	"github.com/nuomiiiii/lite/utils"
	"github.com/nuomiiiii/lite/web/api/remote"
)

func handleMCP(c *gin.Context) {
	if abortIfMCPDisabled(c) {
		return
	}
	applyMCORS(c)
	c.Header("Cache-Control", "no-store")
	if siteAPIKey(c) {
		mcpChallenge(c, "invalid_token", ErrAPIKeyForbidden.Error())
		return
	}
	plain := bearerToken(c)
	if plain == "" {
		mcpChallenge(c, "invalid_token", "MCP access token is required")
		return
	}
	now := time.Now().UTC()
	_, lease, err := lookupAccess(plain, now)
	if err != nil {
		mcpChallenge(c, "invalid_token", "MCP access token is invalid or expired")
		return
	}
	if abortIfMCPDisabled(c) {
		return
	}
	if !remote.RemoteManagementEnabled() {
		mcpChallenge(c, "invalid_token", ErrRemoteDisabled.Error())
		return
	}
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, 2<<20))
	if err != nil {
		c.JSON(http.StatusBadRequest, jsonRPCError(nil, -32700, "failed to read request"))
		return
	}
	messages, batch, err := parseJSONRPC(body)
	if err != nil {
		c.JSON(http.StatusBadRequest, jsonRPCError(nil, -32700, "parse error"))
		return
	}
	results := make([]any, 0, len(messages))
	for _, message := range messages {
		if _, hasID := message["id"]; !hasID {
			continue
		}
		results = append(results, dispatchRPC(c, lease, message))
	}
	if batch {
		c.JSON(http.StatusOK, results)
		return
	}
	if len(results) == 0 {
		c.Status(http.StatusAccepted)
		return
	}
	c.JSON(http.StatusOK, results[0])
}

func dispatchRPC(c *gin.Context, lease models.MCPLease, message map[string]any) gin.H {
	id := message["id"]
	method, _ := message["method"].(string)
	params, _ := message["params"].(map[string]any)
	switch method {
	case "initialize":
		return jsonRPCResult(id, gin.H{
			"protocolVersion": "2025-11-25",
			"capabilities": gin.H{
				"tools": gin.H{"listChanged": false},
			},
			"serverInfo": gin.H{
				"name":    "Lite",
				"version": utils.CurrentVersion,
			},
			"instructions": "This MCP authorization grants terminal, exec, file management, and nodemgt (inbounds, outbounds, routes, forwarding chains, sync, and connectivity tests) on the selected Lite nodes until it expires or is revoked. It is not an administrator account.",
		})
	case "ping":
		return jsonRPCResult(id, gin.H{})
	case "tools/list":
		return jsonRPCResult(id, gin.H{"tools": toolDescriptors()})
	case "tools/call":
		name, _ := params["name"].(string)
		args, _ := params["arguments"].(map[string]any)
		result, err := callTool(c, lease, name, args)
		if err != nil {
			return jsonRPCResult(id, gin.H{
				"content": []gin.H{{"type": "text", "text": err.Error()}},
				"isError": true,
			})
		}
		encoded, _ := json.Marshal(result)
		return jsonRPCResult(id, gin.H{
			"content":           []gin.H{{"type": "text", "text": string(encoded)}},
			"structuredContent": result,
			"isError":           false,
		})
	default:
		return jsonRPCError(id, -32601, "method not found")
	}
}
