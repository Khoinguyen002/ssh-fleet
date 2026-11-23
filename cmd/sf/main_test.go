package main

import "testing"

func TestParseExecArgs(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		want    execOpts
		wantErr bool
	}{
		{
			name: "target with dash-dash and flags command",
			args: []string{"khoi", "--", "ls", "-la"},
			want: execOpts{targetQuery: "khoi", command: "ls -la", waitSec: 45},
		},
		{
			name: "target without dash-dash",
			args: []string{"khoi", "ls", "-la"},
			want: execOpts{targetQuery: "khoi", command: "ls -la", waitSec: 45},
		},
		{
			name: "flags before target with dash-dash",
			args: []string{"--wake", "--cwd", "/tmp", "khoi", "--", "echo", "hi"},
			want: execOpts{targetQuery: "khoi", command: "echo hi", dir: "/tmp", wakeFirst: true, waitSec: 45},
		},
		{
			name: "flags after target before dash-dash",
			args: []string{"khoi", "--cwd", "/tmp", "--timeout", "10", "--", "uname", "-a"},
			want: execOpts{targetQuery: "khoi", command: "uname -a", dir: "/tmp", waitSec: 45, timeoutSec: 10},
		},
		{
			name: "short no-stdin flag",
			args: []string{"-n", "khoi", "hostname"},
			want: execOpts{targetQuery: "khoi", command: "hostname", waitSec: 45, noStdin: true},
		},
		{
			name:    "missing target and command",
			args:    nil,
			wantErr: true,
		},
		{
			name:    "missing command with dash-dash",
			args:    []string{"khoi", "--"},
			wantErr: true,
		},
		{
			name:    "missing command without dash-dash",
			args:    []string{"khoi"},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseExecArgs(tc.args)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}
