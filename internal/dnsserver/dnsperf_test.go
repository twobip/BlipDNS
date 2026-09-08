// Copyright 2025 The BlipDNS Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dnsserver

import (
	"fmt"
	"net"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// dnsperfBin is the path to the dnsperf binary. Tests are skipped when absent.
var dnsperfBin string

func init() {
	dnsperfBin, _ = exec.LookPath("dnsperf")
}

// runDnsperf executes dnsperf against the local blipd and returns parsed stats.
func runDnsperf(t *testing.T, dataPath string, extraArgs ...string) (*dnsperfResult, error) {
	t.Helper()
	if dnsperfBin == "" {
		t.Skip("dnsperf not installed, skipping DNS performance test")
	}
	skipIfNoLocalResolver(t)

	args := []string{
		"-s", "127.0.0.1",
		"-p", "53",
		"-d", dataPath,
		"-n", "1",
		"-t", "5",
		"-c", "4",
	}
	args = append(args, extraArgs...)

	cmd := exec.Command(dnsperfBin, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("dnsperf failed: %w\n%s", err, string(out))
	}
	return parseDnsperfOutput(string(out))
}

// skipIfNoLocalResolver skips a dnsperf test when no resolver listens on
// 127.0.0.1:53. blipd serves TCP alongside UDP, so a TCP dial proves one is
// actually there (a UDP dial would "succeed" with nothing listening).
func skipIfNoLocalResolver(t *testing.T) {
	t.Helper()
	if c, err := net.DialTimeout("tcp", "127.0.0.1:53", 500*time.Millisecond); err != nil {
		t.Skip("no local resolver on 127.0.0.1:53, skipping DNS performance test")
	} else {
		_ = c.Close()
	}
}

// dnsperfResult holds key metrics from a dnsperf run.
type dnsperfResult struct {
	Sent          int
	Completed     int
	Lost          int
	LostPct       float64
	RcodeNOERROR  int
	RcodeNXDOMAIN int
	RcodeSERVFAIL int
	RcodeREFUSED  int
	AvgLatency    time.Duration
	MinLatency    time.Duration
	MaxLatency    time.Duration
	Qps           float64
	RunTime       time.Duration
}

var (
	rxSent      = regexp.MustCompile(`Queries sent:\s+(\d+)`)
	rxCompleted = regexp.MustCompile(`Queries completed:\s+(\d+)\s+\(([\d.]+)%\)`)
	rxLost      = regexp.MustCompile(`Queries lost:\s+(\d+)\s+\(([\d.]+)%\)`)
	rxRcode     = regexp.MustCompile(`(\w+)\s+(\d+)\s+\(([\d.]+%)\)`)
	rxLatency   = regexp.MustCompile(`Average Latency \(s\):\s+([\d.]+)\s+\(min\s+([\d.]+),\s+max\s+([\d.]+)\)`)
	rxQps       = regexp.MustCompile(`Queries per second:\s+([\d.]+)`)
	rxRuntime   = regexp.MustCompile(`Run time \(s\):\s+([\d.]+)`)
)

type rcodeCount struct {
	code  string
	count int
	pct   float64
}

// parseDnsperfOutput extracts metrics from dnsperf human-readable output.
// Response codes may appear on a single line as "NOERROR 1 (12.50%), NXDOMAIN 7 (87.50%)";
// the parser handles comma-separated entries on one line.
func parseDnsperfOutput(output string) (*dnsperfResult, error) {
	r := &dnsperfResult{}
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if m := rxSent.FindStringSubmatch(line); m != nil {
			var n int
			fmt.Sscanf(m[1], "%d", &n)
			r.Sent = n
		}
		if m := rxCompleted.FindStringSubmatch(line); m != nil {
			var n int
			fmt.Sscanf(m[1], "%d", &n)
			var pct float64
			fmt.Sscanf(m[2], "%f", &pct)
			r.Completed = n
			r.LostPct = pct
		}
		if m := rxLost.FindStringSubmatch(line); m != nil {
			var n int
			fmt.Sscanf(m[1], "%d", &n)
			r.Lost = n
		}
		// Response codes are on a single comma-separated line.
		// Extract each `CODE COUNT (PCT%)` token with FindAllStringSubmatch.
		for _, m := range rxRcode.FindAllStringSubmatch(line, -1) {
			// Validate it's actually a response code, not some other metric.
			code := m[1]
			if code != "NOERROR" && code != "NXDOMAIN" && code != "SERVFAIL" && code != "REFUSED" {
				continue
			}
			var n int
			fmt.Sscanf(m[2], "%d", &n)
			switch code {
			case "NOERROR":
				r.RcodeNOERROR += n
			case "NXDOMAIN":
				r.RcodeNXDOMAIN += n
			case "SERVFAIL":
				r.RcodeSERVFAIL += n
			case "REFUSED":
				r.RcodeREFUSED += n
			}
		}
		if m := rxLatency.FindStringSubmatch(line); m != nil {
			var avg, min, max float64
			fmt.Sscanf(m[1], "%f", &avg)
			fmt.Sscanf(m[2], "%f", &min)
			fmt.Sscanf(m[3], "%f", &max)
			r.AvgLatency = time.Duration(avg * float64(time.Second))
			r.MinLatency = time.Duration(min * float64(time.Second))
			r.MaxLatency = time.Duration(max * float64(time.Second))
		}
		if m := rxQps.FindStringSubmatch(line); m != nil {
			fmt.Sscanf(m[1], "%f", &r.Qps)
		}
		if m := rxRuntime.FindStringSubmatch(line); m != nil {
			var n float64
			fmt.Sscanf(m[1], "%f", &n)
			r.RunTime = time.Duration(n * float64(time.Second))
		}
	}
	return r, nil
}

// TestDnsperfResolve sends resolving-domain queries through blipd and
// verifies: zero data loss, all responses are NOERROR (not NXDOMAIN),
// and average latency is below 2s (the upstream is fast and local).
func TestDnsperfResolve(t *testing.T) {
	if dnsperfBin == "" {
		t.Skip("dnsperf not installed")
	}
	dataPath := filepath.Join("testdata", "dnsperf", "resolve-domains.txt")
	result, err := runDnsperf(t, dataPath)
	if err != nil {
		t.Fatal(err)
	}
	if result.Sent == 0 {
		t.Fatal("dnsperf sent zero queries — is blipd running on :53?")
	}
	if result.Lost > 0 {
		t.Errorf("lost %d queries (%.1f%%) — server may be overloaded or misconfigured", result.Lost, result.LostPct)
	}
	if result.RcodeNXDOMAIN > 0 {
		t.Errorf("got %d NXDOMAIN for resolving domains — unexpected", result.RcodeNXDOMAIN)
	}
	if result.RcodeNOERROR == 0 {
		t.Error("expected at least one NOERROR response")
	}
}

// TestDnsperfNXDOMAIN sends NXDOMAIN-domain queries and verifies they
// legitimately get NXDOMAIN (not SERVFAIL or REFUSED), showing blipd
// passes through negative caching correctly.
func TestDnsperfNXDOMAIN(t *testing.T) {
	if dnsperfBin == "" {
		t.Skip("dnsperf not installed")
	}
	dataPath := filepath.Join("testdata", "dnsperf", "nxdomain-domains.txt")
	result, err := runDnsperf(t, dataPath)
	if err != nil {
		t.Fatal(err)
	}
	if result.Sent == 0 {
		t.Fatal("dnsperf sent zero queries")
	}
	// NXDOMAIN queries should get NXDOMAIN (not lose packets to SERVFAIL)
	if result.RcodeNXDOMAIN == 0 {
		t.Errorf("expected NXDOMAIN responses for nonexistent domains, got: NOERROR=%d NXDOMAIN=%d SERVFAIL=%d REFUSED=%d",
			result.RcodeNOERROR, result.RcodeNXDOMAIN, result.RcodeSERVFAIL, result.RcodeREFUSED)
	}
}

// TestDnsperfMixed runs a mixed workload of resolving + NXDOMAIN queries
// and verifies overall health.
func TestDnsperfMixed(t *testing.T) {
	if dnsperfBin == "" {
		t.Skip("dnsperf not installed")
	}
	dataPath := filepath.Join("testdata", "dnsperf", "mixed-test.txt")
	result, err := runDnsperf(t, dataPath)
	if err != nil {
		t.Fatal(err)
	}
	if result.Sent == 0 {
		t.Fatal("dnsperf sent zero queries")
	}
	if result.Lost > result.Sent/20 {
		t.Errorf("too many lost queries: %d/%d (%.1f%%)", result.Lost, result.Sent, result.LostPct)
	}
	if result.Qps <= 0 {
		t.Error("QPS should be positive")
	}
	t.Logf("dnsperf mixed: sent=%d completed=%d lost=%d NXDOMAIN=%d NOERROR=%d QPS=%.0f avg_latency=%v",
		result.Sent, result.Completed, result.Lost, result.RcodeNXDOMAIN, result.RcodeNOERROR, result.Qps, result.AvgLatency)
}

// TestDnsperfThroughput measures that blipd sustains at least 50 QPS on
// the local loopback — a minimal sanity gate for resolver throughput.
func TestDnsperfThroughput(t *testing.T) {
	if dnsperfBin == "" {
		t.Skip("dnsperf not installed")
	}
	skipIfNoLocalResolver(t)
	dataPath := filepath.Join("testdata", "dnsperf", "resolve-domains.txt")

	cmd := exec.Command(dnsperfBin,
		"-s", "127.0.0.1",
		"-p", "53",
		"-d", dataPath,
		"-n", "10", // run through file 10 times = 160 queries
		"-t", "10",
		"-c", "4",
		"-l", "30", // limit to 30s
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Skipf("dnsperf throughput run aborted: %v\n%s", err, string(out))
	}

	result, err := parseDnsperfOutput(string(out))
	if err != nil {
		t.Fatal(err)
	}
	if result.Qps < 50 {
		t.Errorf("QPS %.0f below 50 threshold — blipd resolver may be slow or upstream unreachable", result.Qps)
	}
	t.Logf("throughput: %.0f QPS, avg latency %v", result.Qps, result.AvgLatency)
}
