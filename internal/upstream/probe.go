// ProbeResult / ProbeServer: one-shot "does this upstream answer?" checks used
// by the blipc "Test" button (POST /api/upstream/test). Kept here so spec
// parsing, timeout defaults and query construction stay next to the resolvers.
package upstream

import (
	"context"
	"fmt"
	"net"
	"net/url"
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
// The per-server timeout (TimeoutSec, default 5s) bounds the query itself; a
// DoH endpoint's bootstrap lookup runs first on the caller's context, so a
// slow bootstrap can't eat the query's budget and surface as a misleading
// "context deadline exceeded". Hostname endpoints without a bootstrap still
// resolve via the system resolver inside the dial.
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
	// Warm a hostname DoH endpoint through bootstrap on the caller's context,
	// then pin the timed query's dial to the warmed IPs: otherwise the
	// bootstrap A+AAAA lookups burn the per-server budget and a slow bootstrap
	// surfaces as a misleading "context deadline exceeded". DoH resolvers
	// built without a bootstrap dial via the system resolver (which this can't
	// pre-warm); IP literals need no lookup at all. A failed warm-up is
	// advisory — the query below retries through bootstrap — so only a dead
	// caller context aborts here.
	if doh, ok := r.(*DoHResolver); ok && doh.bootstrap != nil {
		if host := endpointHost(doh.endpoint); host != "" && net.ParseIP(host) == nil {
			pinned, werr := warmDoHEndpoint(ctx, doh, timeout, host)
			if werr != nil {
				res.Error = werr.Error()
				return res
			}
			if pinned != nil {
				r = pinned
			}
		}
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	resp, err := resolveWithRetry(ctx, r, fqdn)
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

// endpointHost extracts the hostname from a DoH endpoint URL ("https://host/path").
func endpointHost(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// warmDoHEndpoint resolves host through doh's bootstrap on the caller's
// context and rebuilds the resolver pinned to those IPs, so the timed query's
// dial skips lookup and the per-server timeout covers the query alone. A nil
// resolver means warm-up failed but was advisory (the query retries through
// bootstrap); only a dead caller context returns an error.
func warmDoHEndpoint(ctx context.Context, doh *DoHResolver, timeout time.Duration, host string) (Resolver, error) {
	ips := bootstrapLookupIP(ctx, doh.bootstrap, host)
	if len(ips) == 0 {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("bootstrap resolve %q: %v", host, ctx.Err())
		}
		return nil, nil
	}
	pinned := NewDoHWithBootstrap(doh.endpoint, timeout, &staticResolver{host: host, ips: ips})
	return pinned, nil
}

// resolveWithRetry sends one A query for fqdn via r, retrying once on a
// mid-connection TCP reset. Fresh TLS handshakes against throttling upstreams
// (Quad9) RST intermittently; the retry opens a new connection and usually
// succeeds. Only resets retry — timeouts, 403s and DNS errors return as-is.
func resolveWithRetry(ctx context.Context, r Resolver, fqdn string) (*dns.Msg, error) {
	q := new(dns.Msg)
	q.SetQuestion(fqdn, dns.TypeA)
	resp, err := r.Resolve(ctx, q)
	if err != nil && isConnReset(err) {
		q = new(dns.Msg)
		q.SetQuestion(fqdn, dns.TypeA)
		resp, err = r.Resolve(ctx, q)
	}
	return resp, err
}

// isConnReset reports whether err is a mid-connection TCP reset — the
// signature of an upstream throttling fresh handshakes, worth one retry.
// Timeouts and DNS-level failures are not resets and must not retry.
func isConnReset(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "connection reset by peer")
}

// staticResolver answers one hostname from a fixed IP list. Probe-only: it
type staticResolver struct {
	host string
	ips  []net.IP
}

func (s *staticResolver) Resolve(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetReply(q)
	if len(q.Question) != 1 || q.Question[0].Name != dns.Fqdn(s.host) {
		return m, nil
	}
	hdr := dns.RR_Header{Name: q.Question[0].Name, Rrtype: q.Question[0].Qtype, Class: dns.ClassINET, Ttl: 60}
	for _, ip := range s.ips {
		switch q.Question[0].Qtype {
		case dns.TypeA:
			if ip.To4() != nil {
				m.Answer = append(m.Answer, &dns.A{Hdr: hdr, A: ip.To4()})
			}
		case dns.TypeAAAA:
			if ip.To4() == nil {
				m.Answer = append(m.Answer, &dns.AAAA{Hdr: hdr, AAAA: ip})
			}
		}
	}
	return m, nil
}
