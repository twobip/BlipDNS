package filter

import "errors"

// ErrPolicyID is returned when a policy has no ID.
var ErrPolicyID = errors.New("filter: policy requires a non-empty id")

// NetError wraps a CIDR parse failure.
type NetError struct {
	Net string
	Err error
}

func (e *NetError) Error() string {
	return "filter: invalid network " + e.Net + ": " + e.Err.Error()
}

func (e *NetError) Unwrap() error { return e.Err }
