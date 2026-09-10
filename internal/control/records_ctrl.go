package control

// RecordController is the piece of the DNS server the management API can
// reconfigure at runtime: static local DNS records (A, AAAA, CNAME) that are
// answered directly instead of being forwarded upstream. The controller pushes
// them from the Local Records page and reads the active set back via stats so
// its poll loop can converge a restarted instance (mirroring the cache and
// rate-limit controllers).
type RecordController interface {
	// SetRecords replaces the instance's local DNS records. Passing nil or
	// an empty slice clears all local records.
	SetRecords(records []RecordEntry) error
	// GetRecords returns the instance's current local DNS records.
	GetRecords() ([]RecordEntry, error)
}
