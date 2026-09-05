// ProbeResult / ProbeServer: one-shot "does this upstream answer?" checks used
// by the blipc "Test" button (POST /api/upstream/test). Kept here so spec
// parsing, timeout defaults and query construction stay next to the resolvers.
package upstream

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// ProbeResult is the outcome of a single test query against one upstream.
type ProbeResult struct {
	Name      string   `json:"name"`
	Address   string   `json:"address"`
	OK        bool     `json:"ok"`
	LatencyMs int64    `json:"latency_ms,omitempty"`
	Answers   []string `json:"answers,omitempty"`
	Rcode     string   `json:"rcode,omitempty"`
	Error     string   `json:"error,omitempty"`
}

// ProbeServer sends one A query for qname to sv and reports what happened.
// It uses the system resolver for DoH endpoint hostnames; use
// ProbeServerWithBootstrap when bootstrap resolvers are configured.
func ProbeServer(ctx context.Context, sv UpstreamServer, qname string) ProbeResult {
	return ProbeServerWithBootstrap(ctx, sv, qname, nil)
}

// ProbeServerWithBootstrap is ProbeServer but resolves a DoH endpoint's own
// hostname through bootstrap (typically the fleet's bootstrap servers) instead
// of the system resolver. A DNS-level answer (even NXDOMAIN/SERVFAIL) counts
// as reachable (OK=true); only transport errors and timeouts fail the probe.
// The per-server timeout (TimeoutSec, default 5s) bounds the call.
func ProbeServerWithBootstrap(ctx context.Context, sv UpstreamServer, qname string, bootstrap Resolver) ProbeResult {
	res := ProbeResult{Name: sv.Name, Address: sv.Address}
	fqdn := dns.Fqdn(strings.TrimSpace(qname))
	if _, ok := dns.IsDomainName(fqdn); !ok {
		res.Error = fmt.Sprintf("invalid domain %q", qname)
		return res
	}
	timeout := timeoutForServer(sv)
	r, err := fromServerSpecWithBootstrap(sv.Address, timeout, bootstrap)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	q := new(dns.Msg)
	q.SetQuestion(fqdn, dns.TypeA)
	start := time.Now()
	resp, err := r.Resolve(ctx, q)
	res.LatencyMs = time.Since(start).Milliseconds()
	if err != nil {
		res.Error = err.Error()
		return res
	}
	if resp == nil {
		res.Error = "empty response"
		return res
	}
	res.Rcode = dns.RcodeToString[resp.Rcode]
	for _, rr := range resp.Answer {
		res.Answers = append(res.Answers, rr.String())
	}
	res.OK = true
	return res
}
