// Package blocklist implements a simple global DNS blocklist.
// Domains are matched exactly or as subdomains (same semantics
// as filter.Policy block/allow lists) but apply to ALL clients.
package blocklist

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// Blocklist holds a set of domains to block.
// It is safe for concurrent use.
type Blocklist struct {
	mu      sync.RWMutex
	domains map[string]bool // domain -> true (we only store the domain, matching is done via IsBlocked)
	onChange func([]string) // called with the current list when the list changes
}

// New creates an empty blocklist.
func New() *Blocklist {
	return &Blocklist{
		domains: make(map[string]bool),
	}
}

// SetOnChange sets the function to call when the blocklist changes.
func (b *Blocklist) SetOnChange(fn func([]string)) {
	b.mu.Lock()
	b.onChange = fn
	b.mu.Unlock()
}

// FromDomains replaces the current list with the given domains.
// It normalizes each domain (lowercase, trim dot) and ignores invalid ones.
func (b *Blocklist) FromDomains(list []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.domains = make(map[string]bool)
	for _, d := range list {
		if d := normalizeDomain(d); d != "" {
			b.domains[d] = true
		}
	}
	if b.onChange != nil {
		go b.onChange(b.List())
	}
}

// Add adds a domain to the blocklist.
func (b *Blocklist) Add(domain string) {
	if d := normalizeDomain(domain); d != "" {
		b.mu.Lock()
		b.domains[d] = true
		b.mu.Unlock()
		if b.onChange != nil {
			go b.onChange(b.List())
		}
	}
}

// Remove removes a domain from the blocklist.
func (b *Blocklist) Remove(domain string) {
	if d := normalizeDomain(domain); d != "" {
		b.mu.Lock()
		delete(b.domains, d)
		b.mu.Unlock()
		if b.onChange != nil {
			go b.onChange(b.List())
		}
	}
}

// List returns a slice of all domains in the blocklist.
func (b *Blocklist) List() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]string, 0, len(b.domains))
	for d := range b.domains {
		out = append(out, d)
	}
	return out
}

// IsBlocked reports whether the given host (e.g., from a DNS query) is blocked.
// It checks if the host ends with any blocked domain (with a dot boundary).
func (b *Blocklist) IsBlocked(host string) bool {
	if host == "" {
		return false
	}
	h := strings.TrimSuffix(host, ".") // normalize
	b.mu.RLock()
	defer b.mu.RUnlock()
	for d := range b.domains {
		if d == h || strings.HasSuffix(h, "."+d) {
			return true
		}
	}
	return false
}

// LoadFromURL fetches the given URL, parses it as an AdBlock Plus filter list,
// and replaces the current blocklist with the parsed domains.
// ctx is used for cancellation and timeout.
func (b *Blocklist) LoadFromURL(ctx context.Context, rawURL string) error {
	if rawURL == "" {
		return errors.New("empty URL")
	}
	// Parse URL to validate
	if _, err := url.ParseRequestURI(rawURL); err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	// Set a reasonable User-Agent to avoid being blocked by some servers.
	req.Header.Set("User-Agent", "blipdns-blocklist/1.0")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var buf strings.Builder
	if _, err := io.Copy(&buf, resp.Body); err != nil {
		return err
	}
	content := buf.String()

	domains := parseABPList(content)
	if len(domains) == 0 {
		return errors.New("no domains parsed from list")
	}
	b.FromDomains(domains)
	return nil
}

// parseABPList extracts domains to block from an AdBlock Plus filter list.
// It supports:
//   - Lines starting with ! are comments and are ignored.
//   - Lines containing ||<domain>^ (with optional $options after ^) are treated as blocking the domain and subdomains.
//   - Lines containing |<http://<domain>> (with optional ^ and $options) are treated similarly.
//   - Plain domains (without anchors) are also blocked (and subdomains).
//   - Anything else is ignored.
func parseABPList(content string) []string {
	var domains []string
	seen := make(map[string]struct{})
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "!") {
			continue
		}
		// Remove any inline comment (not standard in ABP but some lists have it)
		if idx := strings.Index(line, "!"); idx != -1 {
			line = line[:idx]
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
		}
		// Split at the first $ to remove options
		if idx := strings.Index(line, "$"); idx != -1 {
			line = line[:idx]
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
		}
		// Now we have the pattern part.
		// Remove leading | characters (one or two) but keep track of anchoring.
		// We only care about extracting the domain.
		hasDoublePipe := strings.HasPrefix(line, "||")
		hasSinglePipe := strings.HasPrefix(line, "|")
		if hasDoublePipe {
			line = strings.TrimPrefix(line, "||")
		} else if hasSinglePipe {
			line = strings.TrimPrefix(line, "|")
		}
		// Remove trailing ^ if present (it separates domain from next char in regex)
		if idx := strings.Index(line, "^"); idx != -1 {
			line = line[:idx]
		}
		// Now line may contain a URL or just a domain.
		// If it contains ://, try to extract the host.
		if strings.Contains(line, "://") {
			u, err := url.Parse(line)
			if err == nil && u.Hostname() != "" {
				if h := normalizeDomain(u.Hostname()); h != "" {
					if _, exists := seen[h]; !exists {
						seen[h] = struct{}{}
						domains = append(domains, h)
					}
				}
				continue
			}
			// If URL parsing fails, fall back to treating as domain.
		}
		// Otherwise, treat the whole string as a domain (maybe with dots).
		if h := normalizeDomain(line); h != "" {
			if _, exists := seen[h]; !exists {
				seen[h] = struct{}{}
				domains = append(domains, h)
			}
		}
	}
	return domains
}

// normalizeDomain returns a lowercase domain with trailing dot removed.
// It returns empty string if the input is empty or not a valid domain (too simple).
func normalizeDomain(s string) string {
	if s == "" {
		return ""
	}
	s = strings.TrimSpace(s)
	s = strings.ToLower(s)
	s = strings.TrimSuffix(s, ".")
	// Very basic validation: must contain at least one dot and not start/end with dot.
	if strings.Count(s, ".") < 1 {
		return ""
	}
	// Disallow empty labels (like .. or . at start/end already trimmed)
	parts := strings.Split(s, ".")
	for _, p := range parts {
		if p == "" {
			return ""
		}
	}
	return s
}