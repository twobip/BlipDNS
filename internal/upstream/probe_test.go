package upstream

import (
	"context"
	"testing"
	"time"
)

func TestProbeServerInvalidDomain(t *testing.T) {
	res := ProbeServer(context.Background(), UpstreamServer{Name: "x", Address: "udp://9.9.9.9:53"}, "not a domain!!")
	if res.OK {
		t.Fatal("invalid domain should not probe OK")
	}
	if res.Error == "" {
		t.Fatal("invalid domain should set Error")
	}
}

func TestProbeServerInvalidSpec(t *testing.T) {
	// No network involved: spec parsing fails before any dial.
	res := ProbeServer(context.Background(), UpstreamServer{Name: "bogus", Address: "bogus://example"}, "example.com")
	if res.OK {
		t.Fatal("invalid spec should not probe OK")
	}
	if res.Error == "" {
		t.Fatal("invalid spec should set Error")
	}
	if res.Name != "bogus" || res.Address != "bogus://example" {
		t.Fatalf("result should echo name/address, got %+v", res)
	}
}

func TestProbeServerUnreachable(t *testing.T) {
	// Discard-port UDP on loopback refuses fast without external network.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res := ProbeServer(ctx, UpstreamServer{Name: "dead", Address: "udp://127.0.0.1:1", TimeoutSec: 2}, "example.com")
	if res.OK {
		t.Fatalf("unreachable server should not probe OK: %+v", res)
	}
	if res.Error == "" {
		t.Fatal("unreachable server should set Error")
	}
}
