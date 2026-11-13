package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/egressroute"
	actool "github.com/Autumn-27/norma/tool"
)

type egressToolGuard func(context.Context, string, actool.CoreTool, *db.Tool, json.RawMessage, *actool.ToolContext) error

// guardedEgressTool wraps the final resolved tool, including row-less Bash,
// interactive shells and deferred MCP tools. Its metadata and permission
// methods remain the original tool's methods through the embedded interface.
type guardedEgressTool struct {
	actool.CoreTool
	agentKey string
	row      *db.Tool
	runInfo  agent.RunInfo
	guards   []egressToolGuard
}

func guardResolvedTools(ctx context.Context, agentKey string, tools []actool.CoreTool, rows map[string]*db.Tool, guards []egressToolGuard) []actool.CoreTool {
	if len(guards) == 0 {
		return tools
	}
	out := make([]actool.CoreTool, 0, len(tools))
	for _, t := range tools {
		out = append(out, &guardedEgressTool{CoreTool: t, agentKey: agentKey, row: rows[t.Name()], runInfo: agent.RunInfoFrom(ctx), guards: guards})
	}
	return out
}

func (t *guardedEgressTool) AcceptsRawInput() bool {
	if raw, ok := t.CoreTool.(interface{ AcceptsRawInput() bool }); ok {
		return raw.AcceptsRawInput()
	}
	return false
}

func (t *guardedEgressTool) Call(ctx context.Context, input json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
	info := agent.RunInfoFrom(ctx)
	if info == (agent.RunInfo{}) && t.runInfo != (agent.RunInfo{}) {
		ctx = agent.WithRunInfo(ctx, t.runInfo)
	}
	agentKey := t.agentKey
	if tc != nil && strings.TrimSpace(tc.AgentID) != "" {
		agentKey = canonicalEgressAgent(tc.AgentID)
	}
	// Some callers omit AgentID even though tool assembly knows the Agent.
	// Carry that same identity into HTTP/custom tools without mutating a shared
	// ToolContext used by concurrent calls.
	if agentKey != "" && (tc == nil || strings.TrimSpace(tc.AgentID) == "") {
		bound := actool.ToolContext{AgentID: agentKey}
		if tc != nil {
			bound = *tc
			bound.AgentID = agentKey
		}
		tc = &bound
	}
	for _, guard := range t.guards {
		if guard == nil {
			continue
		}
		if err := guard(ctx, agentKey, t.CoreTool, t.row, input, tc); err != nil {
			return actool.Errorf(err.Error()), nil
		}
	}
	return t.CoreTool.Call(ctx, input, tc)
}

func toolEgressSeed(ctx context.Context, agentKey string, tc *actool.ToolContext) egressroute.Binding {
	if tc != nil && strings.TrimSpace(tc.AgentID) != "" {
		agentKey = tc.AgentID
	}
	seed := egressroute.Binding{AgentKey: canonicalEgressAgent(agentKey)}
	if taskID := agent.RunInfoFrom(ctx).TaskID; taskID > 0 {
		seed.TaskID = strconv.FormatInt(taskID, 10)
	}
	return seed
}

func (s *Server) guardEgressTool(ctx context.Context, agentKey string, tool actool.CoreTool, row *db.Tool, _ json.RawMessage, tc *actool.ToolContext) error {
	if s == nil || s.m == nil {
		return fmt.Errorf("出口策略不可用；拒绝执行联网工具，不会回退直连")
	}
	name := ""
	if tool != nil {
		name = tool.Name()
	} else if row != nil {
		name = row.Key
	}
	if strings.HasPrefix(strings.ToLower(name), "mcp__") {
		// MCP processes and remote MCP servers do not carry this call's task
		// routing context. A shared browser proxy is not proof of correct egress.
		return validateToolEgress(egressroute.Binding{}, egressroute.DefaultConfig(), name, row)
	}
	if !uncontrolledEgressTool(name, row) && (row == nil || !row.NeedsUDP) {
		// HTTP/WebFetch use the routing gateway for the actual target. Do not
		// resolve an empty/global Tor context here: a task may explicitly use
		// Clash while Tor is stopped, and domain rules need the real URL.
		return nil
	}
	if s.m.routing == nil {
		if row != nil {
			return s.checkToolEgress(row)
		}
		return nil // Legacy Tor-only installs retain their transparent fallback.
	}
	binding, err := s.m.routing.binding(toolEgressSeed(ctx, agentKey, tc))
	if err != nil {
		return err
	}
	return validateToolEgress(binding, s.m.routing.router.Config(), name, row)
}

// checkToolEgressContext is also used by direct custom-tool API calls that do
// not pass through agent tool assembly.
func (s *Server) checkToolEgressContext(ctx context.Context, row *db.Tool, tc *actool.ToolContext) error {
	return s.guardEgressTool(ctx, "", nil, row, nil, tc)
}

func uncontrolledEgressTool(name string, row *db.Tool) bool {
	lower := strings.ToLower(name)
	return lower == "bash" || strings.HasPrefix(lower, "shell_") || strings.HasPrefix(lower, "mcp__") || row != nil && (row.Kind == "command" || row.Kind == "script")
}

func validateToolEgress(binding egressroute.Binding, config egressroute.Config, name string, row *db.Tool) error {
	if row != nil && row.NeedsUDP {
		return fmt.Errorf("出口策略拒绝执行(%s)：统一出口网关不支持此工具需要的 UDP；不会回退直连", name)
	}
	if strings.HasPrefix(strings.ToLower(name), "mcp__") {
		return fmt.Errorf("出口策略拒绝执行(%s)：此 MCP 工具没有携带任务出口上下文的受控适配，无法保证实际出口；请改用 WebFetch 或受控 HTTP 工具；不会静默改走其他出口或直连", name)
	}
	if !uncontrolledEgressTool(name, row) {
		return nil
	}
	strict := false
	switch binding.Mode {
	case "clash", "proxy":
		strict = true
	case "tor":
		// An explicit Tor selection takes precedence over all target rules.
	case "", "inherit":
		for _, rule := range config.Rules {
			if rule.Enabled && (rule.Provider == egressroute.ProviderClash || config.Fallback.Enabled && rule.Provider == egressroute.ProviderTor && rule.AllowFallback) {
				strict = true
				break
			}
		}
	default:
		return fmt.Errorf("出口策略拒绝执行(%s)：无效出口模式 %q；不会回退直连", name, binding.Mode)
	}
	if strict {
		return fmt.Errorf("出口策略拒绝执行(%s)：该工具无法保证遵循指定的 Clash/代理出口或目标分流；请改用 WebFetch 或受控 HTTP 工具；不会静默改走 Tor 或直连", name)
	}
	return nil
}
