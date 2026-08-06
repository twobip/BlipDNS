// Package blocklist implements a global DNS blocklist that can be filled from
// one or more remote sources (AdBlock Plus / hosts-format lists, Pi-hole style).
//
// Lookups walk the host's ancestor labels against a hash set, so matching is
// O(number of labels) regardless of list size. Updates build the new set
// outside the lock and swap it in atomically, so replacing a multi-million
// entry list never stalls in-flight DNS queries.
package blocklist

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// maxSourceBytes caps how much we read from a single source before giving up.
// oisd-style lists are tens of MB; this is a hard safety bound.
const maxSourceBytes = 1 << 30

// maxLineLen bounds a single line in a list (hosts/ABP entries are short).
const maxLineLen = 4 * 1024 * 1024

// safeBlocklistTransport fetches only over plain HTTP(S) to publicly routable
// destinations, blocking SSRF against loopback, link-local, private,
// multicast, and cloud-metadata ranges. The check happens at connect time, so
// DNS rebinding does not bypass it.
var safeBlocklistTransport = &http.Transport{
	Proxy: http.ProxyFromEnvironment,
	DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		if !ssrfEnabled {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		ips, err := net.DefaultResolver.LookupHost(ctx, host)
		if err != nil {
			return nil, err
		}
		d := net.Dialer{}
		for _, ip := range ips {
			if isPrivateIP(net.ParseIP(ip)) {
				continue
			}
			c, err := d.DialContext(ctx, network, net.JoinHostPort(ip, mustPort(addr)))
			if err != nil {
				return nil, err
			}
			return c, nil
		}
		return nil, fmt.Errorf("blocklist source resolves only to non-public addresses")
	},
	ForceAttemptHTTP2:   true,
	MaxIdleConns:        10,
	IdleConnTimeout:     30 * time.Second,
	TLSHandshakeTimeout: 10 * time.Second,
}

func mustPort(addr string) string {
	_, p, err := net.SplitHostPort(addr)
	if err != nil || p == "" {
		return addr
	}
	return p
}

// isPrivateIP reports whether ip is loopback, link-local, private,
// multicast, unspecified, or in the cloud-metadata 169.254.0.0/16 range.
func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	// Private ranges (RFC 1918) and 100.64/10 (RFC 6598 carrier-grade NAT).
	priv := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"}
	for _, p := range priv {
		_, n, _ := net.ParseCIDR(p)
		if n != nil && n.Contains(ip) {
			return true
		}
	}
	// 169.254.0.0/16 (AWS/GCP/Azure metadata)
	if _, n, _ := net.ParseCIDR("169.254.0.0/16"); n != nil && n.Contains(ip) {
		return true
	}
	return false
}

// ssrfEnabled gates the SSRF guard (literal-IP rejection + private-route dial
// check). It is on by default for production; tests that must fetch from
// httptest (127.0.0.1) servers disable it via TestMain.
var ssrfEnabled = true

// validateSourceURL rejects non-http(s) schemes and obviously internal hosts
// before we even dial. The transport-level check is the real guard against DNS
// rebinding; this is a fast early reject for literal IPs.
func validateSourceURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("missing host")
	}
	if ssrfEnabled {
		if h := strings.TrimPrefix(u.Hostname(), "["); net.ParseIP(h) != nil && isPrivateIP(net.ParseIP(h)) {
			return fmt.Errorf("blocklist source must not target a private/metadata address")
		}
	}
	return nil
}

// FetchTransport is the HTTP transport used to retrieve blocklist sources. It
// defaults to safeBlocklistTransport, which denies private/loopback/link-local
// and cloud-metadata destinations (SSRF hardening). Tests that fetch from
// httptest (127.0.0.1) servers swap it for http.DefaultTransport in TestMain.
var FetchTransport http.RoundTripper = safeBlocklistTransport

// Progress reports incremental fetch/parse progress while loading sources.
type Progress struct {
	URL         string // source currently being fetched
	Domains     int    // domains parsed so far across all sources
	SourceDone  int    // sources fully processed so far
	SourceTotal int    // total number of sources
}

// LoadResult describes the outcome of loading one or more sources.
type LoadResult struct {
	Domains   int            // total domains in the merged list
	Sources   int            // sources processed (total)
	Failed    int            // sources that errored
	Errors    []string       // per-source errors ("" for ok, else "<url>: <err>")
	PerSource []SourceResult // per-source breakdown, in source order
}

// SourceResult describes the outcome of a single source fetch.
type SourceResult struct {
	URL     string // source URL
	Domains int    // domains parsed from this source (before cross-list dedupe)
	Err     string // "" on success, else the download/parse error
}

// Blocklist holds a set of domains to block, plus an optional set of allowed
// (whitelisted) domains that take precedence over the block set.
// It is safe for concurrent use.
type Blocklist struct {
	mu    sync.RWMutex
	exact map[string]struct{} // exact domains / ancestor blocks
	wild  map[string]struct{} // roots of "*.root" entries (match strict subdomains only)
	sum   uint64              // order-independent checksum of exact + wild + allow entries
	count int

	allowExact map[string]struct{} // allowed exact domains
	allowWild  map[string]struct{} // allowed "*.root" roots
}

// New creates an empty blocklist.
func New() *Blocklist {
	return &Blocklist{
		exact:      make(map[string]struct{}),
		wild:       make(map[string]struct{}),
		allowExact: make(map[string]struct{}),
		allowWild:  make(map[string]struct{}),
	}
}

// FromDomains replaces the current list with the given domains.
// It normalizes each domain (lowercase, trim dot) and ignores invalid ones.
func (b *Blocklist) FromDomains(list []string) {
	exact, wild := make(map[string]struct{}), make(map[string]struct{})
	for _, d := range list {
		addEntry(d, exact, wild)
	}
	b.swap(exact, wild)
}

// FromDomainsMap replaces the current list with the given set of domains.
// Used by the streaming loader to avoid an extra copy of a large list.
func (b *Blocklist) FromDomainsMap(set map[string]struct{}) {
	exact, wild := make(map[string]struct{}, len(set)), make(map[string]struct{})
	for d := range set {
		addEntry(d, exact, wild)
	}
	b.swap(exact, wild)
}

// swap installs a freshly built set atomically.
func (b *Blocklist) swap(exact, wild map[string]struct{}) {
	b.mu.Lock()
	b.exact = exact
	b.wild = wild
	b.count = len(exact) + len(wild)
	b.recomputeSumLocked()
	b.mu.Unlock()
}

// recomputeSumLocked recalculates the order-independent checksum across the
// block and allow sets. Callers must hold b.mu.
func (b *Blocklist) recomputeSumLocked() {
	sum := uint64(0)
	for d := range b.exact {
		sum += hashString(d)
	}
	for r := range b.wild {
		sum += hashString("*." + r)
	}
	for d := range b.allowExact {
		sum += hashString("allow:" + d)
	}
	for r := range b.allowWild {
		sum += hashString("allow:*." + r)
	}
	b.sum = sum
}

// addEntry normalizes and inserts a single entry (either "domain" or "*.root").
func addEntry(d string, exact, wild map[string]struct{}) {
	d = strings.TrimSpace(strings.ToLower(d))
	if d == "" {
		return
	}
	if strings.HasPrefix(d, "*.") {
		if root := normalizeDomain(d[2:]); root != "" {
			wild[root] = struct{}{}
		}
		return
	}
	if h := normalizeDomain(d); h != "" {
		exact[h] = struct{}{}
	}
}

// Add adds a domain to the blocklist.
func (b *Blocklist) Add(domain string) {
	if d := normalizeDomain(domain); d != "" {
		b.mu.Lock()
		if _, ok := b.exact[d]; !ok {
			b.exact[d] = struct{}{}
			b.sum += hashString(d)
			b.count++
		}
		b.mu.Unlock()
	}
}

// Remove removes a domain from the blocklist.
func (b *Blocklist) Remove(domain string) {
	if d := normalizeDomain(domain); d != "" {
		b.mu.Lock()
		if _, ok := b.exact[d]; ok {
			delete(b.exact, d)
			b.sum -= hashString(d)
			b.count--
		}
		b.mu.Unlock()
	}
}

// SetAllowed replaces the allowed (whitelisted) set. Allowed domains are
// never blocked, even when they appear in the block set or a source list.
func (b *Blocklist) SetAllowed(list []string) {
	exact, wild := make(map[string]struct{}), make(map[string]struct{})
	for _, d := range list {
		addEntry(d, exact, wild)
	}
	b.mu.Lock()
	b.allowExact = exact
	b.allowWild = wild
	b.recomputeSumLocked()
	b.mu.Unlock()
}

// AddAllowed adds a domain to the allowed set.
func (b *Blocklist) AddAllowed(domain string) {
	if d := normalizeDomain(domain); d != "" {
		b.mu.Lock()
		if _, ok := b.allowExact[d]; !ok {
			b.allowExact[d] = struct{}{}
			b.sum += hashString("allow:" + d)
		}
		b.mu.Unlock()
	}
}

// RemoveAllowed removes a domain from the allowed set.
func (b *Blocklist) RemoveAllowed(domain string) {
	if d := normalizeDomain(domain); d != "" {
		b.mu.Lock()
		if _, ok := b.allowExact[d]; ok {
			delete(b.allowExact, d)
			b.sum -= hashString("allow:" + d)
		}
		b.mu.Unlock()
	}
}

// Allowed returns the sorted list of allowed domains.
func (b *Blocklist) Allowed() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]string, 0, len(b.allowExact)+len(b.allowWild))
	for d := range b.allowExact {
		out = append(out, d)
	}
	for r := range b.allowWild {
		out = append(out, "*."+r)
	}
	return out
}

// Count returns the number of entries in the blocklist.
func (b *Blocklist) Count() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.count
}

// List returns a slice of all domains in the blocklist.
func (b *Blocklist) List() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]string, 0, b.count)
	for d := range b.exact {
		out = append(out, d)
	}
	for r := range b.wild {
		out = append(out, "*."+r)
	}
	return out
}

// Checksum returns an order-independent fingerprint of the list, so two lists
// with the same domains always produce the same value (regardless of order).
func (b *Blocklist) Checksum() uint64 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.sum
}

// IsBlocked reports whether the given host (e.g., from a DNS query) is blocked.
// The allowed set is checked first: a whitelisted host (or one of its ancestor
// labels) is never blocked. Otherwise it checks the host itself and each of
// its ancestor labels against the block set, so lookups stay fast even for
// very large lists.
func (b *Blocklist) IsBlocked(host string) bool {
	if host == "" {
		return false
	}
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if h == "" {
		return false
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	if allowMatchLocked(b.allowExact, b.allowWild, h) {
		return false
	}
	a := h
	for {
		if _, ok := b.exact[a]; ok {
			return true
		}
		// A "*.root" entry only matches strict subdomains of root, so skip it
		// when the candidate is the host itself.
		if a != h {
			if _, ok := b.wild[a]; ok {
				return true
			}
		}
		i := strings.IndexByte(a, '.')
		if i < 0 {
			break
		}
		a = a[i+1:]
	}
	return false
}

// allowMatchLocked reports whether name (or an ancestor label) is covered by
// the given allow sets. Callers must hold b.mu.
func allowMatchLocked(exact, wild map[string]struct{}, h string) bool {
	if _, ok := exact[h]; ok {
		return true
	}
	a := h
	for {
		i := strings.IndexByte(a, '.')
		if i < 0 {
			break
		}
		a = a[i+1:]
		// *.root matches strict subdomains only, so the host itself was already
		// covered by the exact check above.
		if _, ok := wild[a]; ok {
			return true
		}
		if _, ok := exact[a]; ok {
			return true
		}
	}
	return false
}

// LoadFromURL fetches the given URL, parses it as an AdBlock Plus or hosts
// format list, and replaces the current blocklist with the parsed domains.
// ctx is used for cancellation and timeout. Kept for single-URL callers.
func (b *Blocklist) LoadFromURL(ctx context.Context, rawURL string) error {
	_, err := b.LoadFromURLs(ctx, []string{rawURL}, nil)
	return err
}

// LoadFromURLs fetches and parses each source (AdBlock Plus or hosts format),
// merges the results, and replaces the current blocklist. Progress is reported
// via opts.Progress after each source completes. A source failing does not
// abort the others; errors are reported in the returned LoadResult. A non-nil
// error is returned only when no domains could be loaded at all.
func (b *Blocklist) LoadFromURLs(ctx context.Context, urls []string, opts *LoadOptions) (*LoadResult, error) {
	if len(urls) == 0 {
		return nil, errors.New("no blocklist sources configured")
	}
	for _, u := range urls {
		if _, err := url.ParseRequestURI(u); err != nil {
			return nil, fmt.Errorf("invalid blocklist source %q: %w", u, err)
		}
	}

	merged := make(map[string]struct{})
	res := &LoadResult{Sources: len(urls)}
	for i, u := range urls {
		per := SourceResult{URL: u}
		set, err := FetchSource(ctx, u)
		if err != nil {
			res.Failed++
			per.Err = err.Error()
			res.Errors = append(res.Errors, fmt.Sprintf("%s: %v", u, err))
		} else {
			for d := range set {
				merged[d] = struct{}{}
			}
			per.Domains = len(set)
			res.Errors = append(res.Errors, "")
		}
		res.PerSource = append(res.PerSource, per)
		if opts != nil && opts.Progress != nil {
			opts.Progress(Progress{URL: u, Domains: len(merged), SourceDone: i + 1, SourceTotal: len(urls)})
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}

	if len(merged) == 0 {
		return res, errors.New("no domains fetched from any source")
	}
	b.FromDomainsMap(merged)
	res.Domains = len(merged)
	return res, nil
}

// LoadOptions configures LoadFromURLs.
type LoadOptions struct {
	Progress func(Progress)
}

// FetchSource fetches a single source (AdBlock Plus or hosts format) and
// returns the parsed domains (and wildcard roots) as a set. An error is
// returned only when the source could not be fetched or parsed at all.
func FetchSource(ctx context.Context, rawURL string) (map[string]struct{}, error) {
	if err := validateSourceURL(rawURL); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "blipdns-blocklist/1.0 (+https://blipdns.local)")

	client := &http.Client{Transport: FetchTransport, Timeout: 2 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}

	set := make(map[string]struct{})
	sc := bufio.NewScanner(io.LimitReader(resp.Body, maxSourceBytes))
	sc.Buffer(make([]byte, 64*1024), maxLineLen)
	for sc.Scan() {
		parseLine(sc.Text(), set)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return set, nil
}

// parseLine extracts a domain (or wildcard root) from a single list line and
// adds it to merged. Returns true if the line yielded a new entry.
func parseLine(line string, merged map[string]struct{}) bool {
	line = strings.TrimSpace(line)
	if line == "" {
		return false
	}
	// Comments: ABP uses "!", hosts files use "#".
	if line[0] == '!' || line[0] == '#' {
		return false
	}
	// hosts-format: "0.0.0.0 <domain>  # comment".
	if isHostsIP(line) {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			host := strings.TrimSuffix(fields[1], ".")
			if h := normalizeDomain(host); h != "" {
				merged[h] = struct{}{}
				return true
			}
		}
		return false
	}
	// Strip any inline comment.
	if idx := strings.IndexAny(line, "!#"); idx != -1 {
		line = strings.TrimSpace(line[:idx])
		if line == "" {
			return false
		}
	}
	// Strip $options.
	if idx := strings.IndexByte(line, '$'); idx != -1 {
		line = strings.TrimSpace(line[:idx])
		if line == "" {
			return false
		}
	}
	// Strip anchor bars, keep track of the "||" prefix for wildcard-ish lines.
	hasDoublePipe := strings.HasPrefix(line, "||")
	line = strings.TrimLeft(line, "|")
	// Strip a trailing "^" (end-of-host separator in ABP).
	if idx := strings.IndexByte(line, '^'); idx != -1 {
		line = line[:idx]
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return false
	}
	// URLs: extract the host.
	if strings.Contains(line, "://") {
		u, err := url.Parse(line)
		if err == nil && u.Hostname() != "" {
			if h := normalizeDomain(u.Hostname()); h != "" {
				merged[h] = struct{}{}
				return true
			}
		}
		return false
	}
	// "||host^" implies blocking host and its subdomains (an exact entry does
	// that via the ancestor walk), so plain normalization suffices.
	if hasDoublePipe {
		if h := normalizeDomain(line); h != "" {
			merged[h] = struct{}{}
			return true
		}
		return false
	}
	// Plain domain or "*." wildcard.
	if strings.HasPrefix(line, "*.") {
		if root := normalizeDomain(line[2:]); root != "" {
			merged["*."+root] = struct{}{}
			return true
		}
		return false
	}
	if h := normalizeDomain(line); h != "" {
		merged[h] = struct{}{}
		return true
	}
	return false
}

// isHostsIP reports whether a line starts with an IP literal (hosts-file form).
func isHostsIP(line string) bool {
	if line == "" {
		return false
	}
	ip := line
	if idx := strings.IndexAny(ip, " \t"); idx != -1 {
		ip = ip[:idx]
	}
	switch ip {
	case "0.0.0.0", "127.0.0.1", "::", "::1", "255.255.255.255", "localhost":
		return true
	}
	return false
}

// NormalizeDomain returns a lowercase domain with trailing dot removed, or ""
// if the input is not a valid domain. Exposed so the controller can key its
// manual-domain store on the same normalized form the blocklist uses.
func NormalizeDomain(s string) string { return normalizeDomain(s) }

// normalizeDomain returns a lowercase domain with trailing dot removed.
// It returns empty string if the input is empty or not a valid domain.
func normalizeDomain(s string) string {
	if s == "" {
		return ""
	}
	s = strings.TrimSpace(s)
	s = strings.ToLower(s)
	s = strings.TrimSuffix(s, ".")
	if strings.Count(s, ".") < 1 {
		return ""
	}
	if s[0] == '.' || s[len(s)-1] == '.' {
		return ""
	}
	for _, p := range strings.Split(s, ".") {
		if p == "" {
			return ""
		}
	}
	return s
}

// cacheFile is the on-disk snapshot: the blocked set plus the allowed set that
// overrides it.
type cacheFile struct {
	Domains []string `json:"domains"`
	Allowed []string `json:"allowed,omitempty"`
}

// SaveCache atomically writes the current list to path as JSON so a restart
// can reload it into RAM without re-fetching the sources.
func (b *Blocklist) SaveCache(path string) error {
	data, err := json.Marshal(cacheFile{Domains: b.List(), Allowed: b.Allowed()})
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	// 0600: cache may reflect queried domains; no group/world access.
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// LoadCache returns a blocklist restored from a previously saved cache file.
// It returns (nil, nil) when no cache exists; a corrupt file is an error.
// Legacy caches (a bare JSON array of domains) are still readable.
func LoadCache(path string) (*Blocklist, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var cf cacheFile
	if err := json.Unmarshal(data, &cf); err != nil {
		var list []string
		if lerr := json.Unmarshal(data, &list); lerr != nil {
			return nil, err
		}
		cf.Domains = list
	}
	bl := New()
	bl.FromDomains(cf.Domains)
	bl.SetAllowed(cf.Allowed)
	return bl, nil
}

// hashString returns an FNV-1a 32-bit hash as a uint64 (for the checksum sum).
func hashString(s string) uint64 {
	h := uint32(2166136261)
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return uint64(h)
}
