package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"path/filepath"
	"runtime"

	"skillguard/internal/assess"
	"skillguard/internal/mcp"
)

type boundedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		return 0, errors.New("output limit")
	}
	return b.Buffer.Write(p)
}

func controlledInstallTool(config, python, script string) (mcp.Entry, error) {
	if runtime.GOOS == "windows" {
		return mcp.Entry{}, errors.New("controlled install MCP requires Unix process-group cancellation; read-only MCP tools support Windows")
	}
	for _, path := range []string{config, python, script} {
		if !filepath.IsAbs(path) {
			return mcp.Entry{}, errors.New("guard paths must be absolute")
		}
	}
	data, err := readMCPConfig(config)
	var fields map[string]json.RawMessage
	var root string
	if err != nil || assess.StrictJSON(data, &fields) != nil || json.Unmarshal(fields["target_root"], &root) != nil {
		return mcp.Entry{}, errors.New("invalid protected guard configuration")
	}
	for _, path := range []string{config, python, script} {
		if !outsideTarget(path, root) {
			return mcp.Entry{}, errors.New("guard configuration and runtime must be outside the target")
		}
	}
	schema := mcpSchema(map[string]any{"argv": map[string]any{"type": "array", "minItems": 1, "maxItems": 512, "items": map[string]any{"type": "string", "maxLength": 8192}}}, "argv")
	entry := mcp.Entry{Tool: mcpTool("skillguard_install_action", "Run one exact argv install ONLY through the protected SkillGuard gate. Withholds execution on review/deny/incomplete or changed inputs. Requires an operator-provided isolated runtime; no shell or model-selected context. Never automatically retry an interrupted call.", schema, false)}
	entry.Call = func(ctx context.Context, args json.RawMessage) (any, error) {
		var input struct {
			Argv []string `json:"argv"`
		}
		if assess.StrictJSON(args, &input) != nil || len(input.Argv) == 0 || len(input.Argv) > 512 {
			return nil, errors.New("invalid install action")
		}
		action := assess.Action{Mode: "argv", Argv: input.Argv}
		payload, _ := json.Marshal(action)
		command := exec.CommandContext(ctx, python, "-I", script, "--config", config) // #nosec G204 -- fixed operator-selected protected runtime; model data only on stdin
		command.Env = []string{}
		command.Stdin = bytes.NewReader(payload)
		command.Stderr = io.Discard
		var output boundedBuffer
		output.limit = 1 << 20
		command.Stdout = &output
		configureGuardProcess(command)
		runErr := command.Run()
		var result map[string]any
		if assess.StrictJSON(output.Bytes(), &result) != nil || ctx.Err() != nil {
			return nil, errors.New("controlled install unavailable or interrupted; inspect state before retrying")
		}
		status, _ := result["status"].(string)
		if status != "executed" && status != "withheld" {
			return nil, errors.New("invalid gate result")
		}
		if runErr != nil && status != "withheld" {
			return nil, errors.New("controlled install failed")
		}
		return result, nil
	}
	return entry, nil
}
