package control

import (
	"fmt"
	"net"
	"net/http"
)

// UpdateStatus describes the most recent remote self-update operation.
type UpdateStatus struct {
	Running   bool   `json:"running"`
	Message   string `json:"message,omitempty"`
	LastError string `json:"last_error,omitempty"`
	Channel   string `json:"channel,omitempty"`
}

// UpdateChannel is the only branch selection accepted by the updater.
type UpdateChannel string

const (
	ChannelStable UpdateChannel = "stable"
	ChannelDev    UpdateChannel = "dev"
)

func ValidUpdateChannel(ch string) bool {
	return ch == string(ChannelStable) || ch == string(ChannelDev)
}

// UpdateController starts a controlled update of the local blipd binary.
type UpdateController interface {
	StartUpdate(channel string) error
	UpdateStatus() UpdateStatus
}

// UpdateStatusReporter is a subset of UpdateController: just enough to check
// whether the local node is mid-update. The HA manager uses it to surface an
// "updating" flag in HAStatus so the controller can lower VRRP priority.
type UpdateStatusReporter interface {
	UpdateStatus() UpdateStatus
}

// ServeLocalUnix serves the passwordless local management handler on ln.
// M10 runtime guard: LocalHandler must ONLY ever serve a Unix socket, where
// the socket file's permissions (0600, service user) are the auth boundary
// (Pi-hole model). Serving it on TCP would expose unauthenticated admin to the
// network. This refuses anything whose network is not "unix" — callers must
// route TCP through Server.Handler (bearer-token gated) instead. Never serve
// LocalHandler on TCP.
func ServeLocalUnix(ln net.Listener, h http.Handler) error {
	if ln == nil {
		return fmt.Errorf("control: local listener is nil")
	}
	if got := ln.Addr().Network(); got != "unix" {
		return fmt.Errorf("control: LocalHandler must only serve a Unix socket (got network %q)", got)
	}
	return http.Serve(ln, h)
}

// MustBeUnixListener is the same guard for call sites that manage their own
// http.Server (e.g. blipd main): it returns an error when ln is not a Unix
// socket so the caller aborts instead of exposing LocalHandler on TCP.
func MustBeUnixListener(ln net.Listener) error {
	if ln == nil {
		return fmt.Errorf("control: local listener is nil")
	}
	if got := ln.Addr().Network(); got != "unix" {
		return fmt.Errorf("control: LocalHandler must only serve a Unix socket (got network %q)", got)
	}
	return nil
}
