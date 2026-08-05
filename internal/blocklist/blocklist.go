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
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// maxSourceBytes caps how much we read from a single source before giving up.
// oisd-style lists are tens of MB; this is a hard safety bound.
const maxSourceBytes = 1 << 30

// maxLineLen bounds a single line in a list (hosts/ABP entries are short).
const maxLineLen = 4 * 1024 * 1024

// Progress reports incremental fetch/parse progress while loading sources.
type Progress struct {
	URL         string // source currently being fetched
	Domains     int    // domains parsed so far across all sources
	SourceDone  int    // sources fully processed so far
	SourceTotal int    // total number of sources
}

// LoadResult describes the outcome of loading one or more sources.
type LoadResult struct {
	Domains int      // total domains in the merged list
	Sources int      // sources processed (total)
	Failed  int      // sources that errored
	Errors  []string // per-source errors ("" for ok, else "<url>: <err>")
}

// Blocklist holds a set of domains to block.
// It is safe for concurrent use.
type Blocklist struct {
	mu    sync.RWMutex
	exact map[string]struct{} // exact domains / ancestor blocks
	wild  map[string]struct{} // roots of "*.root" entries (match strict subdomains only)
	sum   uint64              // order-independent checksum of exact + wild entries
	count int
}

// New creates an empty blocklist.
func New() *Blocklist {
	return &Blocklist{
		exact: make(map[string]struct{}),
		wild:  make(map[string]struct{}),
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
	sum := uint64(0)
	for d := range exact {
		sum += hashString(d)
	}
	for r := range wild {
		sum += hashString("*." + r)
	}
	b.mu.Lock()
	b.exact = exact
	b.wild = wild
	b.sum = sum
	b.count = len(exact) + len(wild)
	b.mu.Unlock()
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
// It checks the host itself and each of its ancestor labels against the set,
// so lookups stay fast even for very large lists.
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
		err := fetchInto(ctx, u, merged)
		if err != nil {
			res.Failed++
			res.Errors = append(res.Errors, fmt.Sprintf("%s: %v", u, err))
		} else {
			res.Errors = append(res.Errors, "")
		}
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

// fetchInto streams one source and adds every parsed domain to merged.
func fetchInto(ctx context.Context, rawURL string, merged map[string]struct{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "blipdns-blocklist/1.0 (+https://blipdns.local)")

	client := &http.Client{Timeout: 2 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}

	sc := bufio.NewScanner(io.LimitReader(resp.Body, maxSourceBytes))
	sc.Buffer(make([]byte, 64*1024), maxLineLen)
	for sc.Scan() {
		parseLine(sc.Text(), merged)
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
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

// hashString returns an FNV-1a 32-bit hash as a uint64 (for the checksum sum).
func hashString(s string) uint64 {
	h := uint32(2166136261)
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return uint64(h)
}
