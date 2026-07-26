// Package blocklist implements a simple global DNS blocklist.
// Domains are matched exactly or as suffixes/wildcards (same semantics
// as filter.Policy block/allow lists) but apply to ALL clients regardless
// of source IP. A blocklist-triggered block is logged with action "BLOCKLIST"
// so it appears in the query log distinct from policy blocks.
package blocklist

import (
	"sort"
	"strings"
	"sync"
)

// Blocklist holds a set of blocked domains.
type Blocklist struct {
	mu        sync.RWMutex
	domains   map[string]struct{} // normalized, lowercased exact/suffix roots
	suffixes  map[string]struct{} // root domains from suffix entries
	wildcards map[string]struct{} // roots from *.wild entries
}

// New creates an empty Blocklist.
func New() *Blocklist {
	return &Blocklist{
		domains:   make(map[string]struct{}),
		suffixes:  make(map[string]struct{}),
		wildcards: make(map[string]struct{}),
	}
}

// FromDomains creates a Blocklist pre-seeded with the given patterns.
func FromDomains(domains []string) *Blocklist {
	b := New()
	for _, d := range domains {
		b.Add(d)
	}
	return b
}

func (b *Blocklist) addLocked(domain string) {
	d := normalize(domain)
	if d == "" {
		return
	}
	if strings.HasPrefix(d, "*.") {
		root := d[2:]
		if root != "" {
			b.wildcards[root] = struct{}{}
		}
		return
	}
	// suffix match: store root domain; also store exact
	b.suffixes[d] = struct{}{}
	b.domains[d] = struct{}{}
}

// Add inserts a domain pattern into the blocklist. Supports exact,
// suffix (example.com matches sub.example.com), and wildcard (*.example.com
// matches sub.example.com but not example.com itself).
func (b *Blocklist) Add(domain string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.addLocked(domain)
}

// Remove deletes a domain pattern from the blocklist.
func (b *Blocklist) Remove(domain string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	d := normalize(domain)
	if d == "" {
		return
	}
	if strings.HasPrefix(d, "*.") {
		delete(b.wildcards, d[2:])
		return
	}
	delete(b.suffixes, d)
	delete(b.domains, d)
}

// Match checks whether name is covered by the blocklist.
func (b *Blocklist) Match(name string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	n := normalize(name)
	if n == "" {
		return false
	}
	if _, ok := b.domains[n]; ok {
		return true
	}
	// suffix match
	labels := strings.Split(n, ".")
	for i := 0; i < len(labels); i++ {
		root := strings.Join(labels[i:], ".")
		if _, ok := b.suffixes[root]; ok {
			return true
		}
	}
	// wildcard match: subdomains only (i >= 1)
	for i := 1; i < len(labels); i++ {
		root := strings.Join(labels[i:], ".")
		if _, ok := b.wildcards[root]; ok {
			return true
		}
	}
	return false
}

// List returns all patterns as a sorted snapshot.
func (b *Blocklist) List() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]string, 0, len(b.domains)+len(b.wildcards))
	for d := range b.domains {
		out = append(out, d)
	}
	for root := range b.wildcards {
		out = append(out, "*."+root)
	}
	sort.Strings(out)
	return out
}

// Len returns the number of stored patterns.
func (b *Blocklist) Len() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.domains) + len(b.wildcards)
}

// Clear removes all patterns.
func (b *Blocklist) Clear() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.domains = make(map[string]struct{})
	b.suffixes = make(map[string]struct{})
	b.wildcards = make(map[string]struct{})
}

// Replace clears the list and adds the given domains.
func (b *Blocklist) Replace(domains []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.domains = make(map[string]struct{})
	b.suffixes = make(map[string]struct{})
	b.wildcards = make(map[string]struct{})
	for _, domain := range domains {
		b.addLocked(domain)
	}
}

func normalize(domain string) string {
	d := strings.ToLower(strings.TrimSpace(domain))
	d = strings.TrimSuffix(d, ".")
	return d
}
