// Package firewall builds and applies the ipset/iptables configuration.
package firewall

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

// ChainName is the name of the custom iptables chain we manage.
const ChainName = "GEOBLOCK"

// Runner executes an external command. stdin, when non-empty, is fed to the
// process. It returns combined stdout (stderr is folded into the error).
type Runner interface {
	Run(ctx context.Context, name string, args []string, stdin string) (string, error)
}

// ExecRunner runs real commands via os/exec.
type ExecRunner struct{}

// Run implements Runner.
func (ExecRunner) Run(ctx context.Context, name string, args []string, stdin string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errb strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		if msg := strings.TrimSpace(errb.String()); msg != "" {
			return out.String(), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, msg)
		}
		return out.String(), fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return out.String(), nil
}

// Call records a single invocation for tests.
type Call struct {
	Name  string
	Args  []string
	Stdin string
}

// FakeRunner records calls and optionally delegates to Respond.
type FakeRunner struct {
	Calls   []Call
	Respond func(name string, args []string, stdin string) (string, error)
}

// Run implements Runner.
func (f *FakeRunner) Run(_ context.Context, name string, args []string, stdin string) (string, error) {
	f.Calls = append(f.Calls, Call{Name: name, Args: append([]string(nil), args...), Stdin: stdin})
	if f.Respond != nil {
		return f.Respond(name, args, stdin)
	}
	return "", nil
}

// DryRunner prints every command (and any stdin payload) without executing
// anything. It satisfies the unexported dryRunAware interface so the Manager
// can skip query-dependent steps.
type DryRunner struct {
	Out io.Writer
}

// DryRun reports that this runner never executes commands.
func (DryRunner) DryRun() bool { return true }

// Run implements Runner.
func (d DryRunner) Run(_ context.Context, name string, args []string, stdin string) (string, error) {
	if d.Out != nil {
		fmt.Fprintf(d.Out, "+ %s %s\n", name, strings.Join(args, " "))
		if stdin != "" {
			fmt.Fprintf(d.Out, "  [stdin]\n")
			for _, line := range strings.Split(strings.TrimRight(stdin, "\n"), "\n") {
				fmt.Fprintf(d.Out, "  | %s\n", line)
			}
		}
	}
	return "", nil
}
