package cmd

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/control/client"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
)

func Test_debugCmd_errors(t *testing.T) {
	type args struct {
		s              *cli.IOStreams
		c              *cobra.Command
		args           []string
		getDiagnostics func(ctx context.Context) (DiagnosticsInfo, error)
	}
	errGetDiagnostics := errors.New("getDiagnostics errored")

	var tests = []struct {
		name string
		args args
		want string
		err  error
	}{
		{
			name: "getDiagnostics error",
			args: args{
				s: cli.NewIOStreams(),
				getDiagnostics: func(_ context.Context) (DiagnosticsInfo, error) {
					return DiagnosticsInfo{}, errGetDiagnostics
				}},
			err: errGetDiagnostics,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := debugCmd(tt.args.s, tt.args.c, tt.args.args, tt.args.getDiagnostics)
			if !errors.Is(err, tt.err) {
				t.Fatalf("unexpected error, want: %v, got: %v", tt.err, err)
			}
		})
	}
}

func Test_debugCmd(t *testing.T) {
	streams, bIn, bOut, bErr := cli.NewTestingIOStreams()

	type callArgs struct {
		streams        *cli.IOStreams
		flags          []string
		args           []string
		getDiagnostics func(ctx context.Context) (DiagnosticsInfo, error)
	}

	diagAgent := func(_ context.Context) (DiagnosticsInfo, error) {
		return DiagnosticsInfo{
			AgentInfo: AgentInfo{PID: 4242},
		}, nil
	}
	diagMulti := func(_ context.Context) (DiagnosticsInfo, error) {
		return DiagnosticsInfo{
			AgentInfo: AgentInfo{PID: 4242},
			ProcMetas: []client.ProcMeta{
				{
					Name: "beat-1",
					PID:  31416,
				},
				{
					Name: "beat-2",
					PID:  1618,
				},
			},
		}, nil
	}

	var tests = []struct {
		name     string
		callArgs callArgs
		bIn      *bytes.Buffer
		want     string
	}{
		{
			name: "only agent",
			callArgs: callArgs{
				streams:        streams,
				getDiagnostics: diagAgent,
			},
			want: `
PIDs:
    elastic-agent:   4242

Delve commands:
    elastic-agent:  dlv --listen=:4242 --headless=true --api-version=2 --accept-multiclient attach 4242
`,
		},
		{
			name: "only agent with port",
			callArgs: callArgs{
				streams:        streams,
				flags:          []string{"--" + flagPort, "31416"},
				getDiagnostics: diagAgent,
			},
			want: `
PIDs:
    elastic-agent:   4242

Delve commands:
    elastic-agent:  dlv --listen=:31416 --headless=true --api-version=2 --accept-multiclient attach 4242
`,
		},
		{
			name: "agent and others applications",
			callArgs: callArgs{
				streams:        streams,
				getDiagnostics: diagMulti,
			},
			want: `
PIDs:
    elastic-agent:   4242
    beat-1:          31416
    beat-2:          1618

Delve commands:
    elastic-agent:  dlv --listen=:4242 --headless=true --api-version=2 --accept-multiclient attach 4242
    beat-1:         dlv --listen=:4242 --headless=true --api-version=2 --accept-multiclient attach 31416
    beat-2:         dlv --listen=:4242 --headless=true --api-version=2 --accept-multiclient attach 1618
`,
		},
		{
			name: "local flag: agent and others applications",
			callArgs: callArgs{
				streams:        streams,
				flags:          []string{"--" + flagLocal},
				getDiagnostics: diagMulti,
			},
			want: `
PIDs:
    elastic-agent:   4242
    beat-1:          31416
    beat-2:          1618

Delve commands:
    elastic-agent:  dlv attach 4242
    beat-1:         dlv attach 31416
    beat-2:         dlv attach 1618
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			cmd := newDebugCommand(tt.callArgs.streams, tt.callArgs.getDiagnostics)
			cmd.SetArgs(tt.callArgs.flags)

			err := cmd.Execute()
			require.NoError(t, err)

			assert.Equal(t, tt.want, bOut.String())
			assert.Empty(t, bErr)

			bOut.Reset()
			bIn.Reset()
		})
	}

}

func Test_debugRunCmd(t *testing.T) {
	streams, _, bOut, bErr := cli.NewTestingIOStreams()

	diagAgent := func(_ context.Context) (DiagnosticsInfo, error) {
		return DiagnosticsInfo{
			AgentInfo: AgentInfo{PID: 4242},
		}, nil
	}

	cmd := newDebugCommand(streams, diagAgent)
	cmd.SetArgs([]string{"run", "elastic-agent"})
	cmd.Execute()
	cmd.SetArgs([]string{"run", "--local", "elastic-agent"})
	cmd.Execute()

	fmt.Println(bOut.String())
	fmt.Println(bErr.String())
}
