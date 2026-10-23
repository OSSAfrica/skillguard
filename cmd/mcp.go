package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"skillguard/internal/assess"
	"skillguard/internal/mcp"
)

func mcpSchema(properties map[string]any, required ...string) any {
	return map[string]any{"type": "object", "properties": properties, "required": required, "additionalProperties": false}
}
func mcpTool(name, description string, schema any, readonly bool) mcp.Tool {
	return mcp.Tool{Name: name, Description: description, InputSchema: schema, OutputSchema: map[string]any{"type": "object"}, Annotations: map[string]any{"readOnlyHint": readonly, "destructiveHint": !readonly, "idempotentHint": readonly, "openWorldHint": name != "skillguard_scan_document"}}
}

func newMCPCommand() *cobra.Command {
	var policyPath, contextPath, guardConfig, pythonPath, guardScript string
	c := &cobra.Command{Use: "mcp", Short: "Serve bounded SkillGuard tools over local MCP stdio", Args: cobra.NoArgs}
	c.Flags().StringVar(&policyPath, "policy", "", "Protected action policy for assessments")
	c.Flags().StringVar(&contextPath, "context", "", "Protected fixed assessment context JSON outside the target")
	c.Flags().StringVar(&guardConfig, "guard-config", "", "Protected controlled-install adapter configuration (explicit execution opt-in)")
	c.Flags().StringVar(&pythonPath, "guard-python", "", "Absolute protected Python interpreter for controlled installs")
	c.Flags().StringVar(&guardScript, "guard-script", "", "Absolute protected guard.py script for controlled installs")
	c.RunE = func(cmd *cobra.Command, _ []string) error {
		if (policyPath == "") != (contextPath == "") {
			return errors.New("MCP assessments require both --policy and --context")
		}
		server := &mcp.Server{Version: Version, Tools: []mcp.Entry{documentTool()}}
		if contextPath != "" {
			if _, err := loadMCPContext(contextPath); err != nil {
				return err
			}
			server.Tools = append(server.Tools, actionTool(policyPath, contextPath))
		}
		if guardConfig != "" || pythonPath != "" || guardScript != "" {
			if guardConfig == "" || pythonPath == "" || guardScript == "" {
				return errors.New("controlled install requires all guard flags")
			}
			entry, err := controlledInstallTool(guardConfig, pythonPath, guardScript)
			if err != nil {
				return err
			}
			server.Tools = append(server.Tools, entry)
		}
		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return server.Serve(ctx, cmd.InOrStdin(), cmd.OutOrStdout())
	}
	return c
}
func init() { rootCmd.AddCommand(newMCPCommand()) }

func documentTool() mcp.Entry {
	schema := mcpSchema(map[string]any{"content": map[string]any{"type": "string", "maxLength": 1 << 20}, "source": map[string]any{"type": "string", "maxLength": 512}}, "content")
	return mcp.Entry{Tool: mcpTool("skillguard_scan_document", "Statically scan untrusted llms.txt, skills or documentation text. No fetching, installation or local dependency-file reads. A score is not execution permission.", schema, true), Call: func(_ context.Context, args json.RawMessage) (any, error) {
		var input struct {
			Content *string `json:"content"`
			Source  string  `json:"source,omitempty"`
		}
		if assess.StrictJSON(args, &input) != nil || input.Content == nil || len(input.Source) > 512 {
			return nil, errors.New("invalid scan input")
		}
		report, _, err := scanInputs([]string{"-"}, 70, strings.NewReader(*input.Content), input.Source)
		if err != nil {
			return nil, err
		}
		return map[string]any{"schema_version": 1, "evidence_trust": "untrusted_data", "execution_authorized": false, "report": report}, nil
	}}
}

type fixedContext struct {
	SchemaVersion  int               `json:"schema_version"`
	TargetRoot     string            `json:"target_root"`
	CWD            string            `json:"cwd"`
	Environment    map[string]string `json:"environment"`
	ContextProfile string            `json:"context_profile"`
	Inputs         []assess.Input    `json:"inputs"`
}

func loadMCPContext(path string) (assess.Request, error) {
	var fixed fixedContext
	data, err := readMCPConfig(path)
	if err != nil || assess.StrictJSON(data, &fixed) != nil {
		return assess.Request{}, errors.New("invalid MCP context")
	}
	request := assess.Request{SchemaVersion: fixed.SchemaVersion, TargetRoot: fixed.TargetRoot, CWD: fixed.CWD, Environment: fixed.Environment, ContextProfile: fixed.ContextProfile, Inputs: fixed.Inputs, Action: assess.Action{Mode: "argv", Argv: []string{"pip"}}}
	raw, _ := json.Marshal(request)
	if _, err = assess.DecodeRequest(raw); err != nil {
		return request, err
	}
	if !outsideTarget(path, request.TargetRoot) {
		return request, errors.New("MCP context must be outside the target")
	}
	return request, nil
}
func outsideTarget(path, root string) bool {
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false
	}
	real, err = filepath.Abs(real)
	if err != nil {
		return false
	}
	target, err := filepath.EvalSymlinks(root)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(target, real)
	return err == nil && rel != "." && !filepath.IsLocal(rel)
}
func readMCPConfig(path string) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- explicitly selected protected operator configuration
	if err != nil {
		return nil, errors.New("MCP configuration unavailable")
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > 64<<10 {
		return nil, errors.New("invalid MCP configuration")
	}
	return io.ReadAll(io.LimitReader(f, 64<<10+1))
}

func actionTool(policyPath, contextPath string) mcp.Entry {
	actionSchema := map[string]any{"type": "object", "properties": map[string]any{"mode": map[string]any{"type": "string", "enum": []string{"argv", "bash"}}, "argv": map[string]any{"type": "array", "maxItems": 512, "items": map[string]any{"type": "string"}}, "command": map[string]any{"type": "string", "maxLength": 65536}}, "required": []string{"mode"}, "additionalProperties": false}
	return mcp.Entry{Tool: mcpTool("skillguard_assess_action", "Assess an exact action using protected operator context and policy. Returns versioned allow/review/deny; never executes. Model-supplied cwd, environment, inputs and policy are rejected.", mcpSchema(map[string]any{"action": actionSchema}, "action"), true), Call: func(ctx context.Context, args json.RawMessage) (any, error) {
		var input struct {
			Action assess.Action `json:"action"`
		}
		if assess.StrictJSON(args, &input) != nil {
			return nil, errors.New("invalid action")
		}
		request, err := loadMCPContext(contextPath)
		if err != nil {
			return nil, err
		}
		request.Action = input.Action
		policy, err := assess.LoadPolicy(policyPath, request.TargetRoot)
		if err != nil {
			return nil, err
		}
		return assess.Evaluate(ctx, request, policy, assess.Options{EngineVersion: Version}), nil
	}}
}
