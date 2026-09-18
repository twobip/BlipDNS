package controller

import (
	"bytes"
	"crypto/rand"
	"encoding/xml"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// handleDoHMobileConfig serves an Apple configuration profile (.mobileconfig)
// that installs this resolver as a DNS-over-HTTPS server on iPhone, iPad and
// Mac (iOS 14 / macOS Big Sur and newer), following the same shape as
// AdGuard Home's /control/dns_info mobileconfig: a com.apple.dnsSettings
// payload with DNSProtocol HTTPS and a ServerURL of
// https://host[:port]/dns-query[/client-id].
//
// Query params: host (required), port (optional, default 443),
// client_id (optional, blipd /dns-query/<id> identity).
func (s *Server) handleDoHMobileConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	host, err := normalizeProfileHost(strings.TrimSpace(q.Get("host")))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	port := 443
	if p := strings.TrimSpace(q.Get("port")); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			http.Error(w, "invalid port (1-65535)", http.StatusBadRequest)
			return
		}
		port = n
	}
	clientID := strings.TrimSpace(q.Get("client_id"))
	// Same rules blipd enforces on /dns-query/<id> (helper.go): short
	// printable token, no path separators or query characters.
	if len(clientID) > 64 || strings.ContainsAny(clientID, "/?# \t") {
		http.Error(w, "invalid client_id (max 64 chars, no /?# or spaces)", http.StatusBadRequest)
		return
	}
	serverURL := "https://" + host
	if port != 443 {
		serverURL += ":" + strconv.Itoa(port)
	}
	serverURL += "/dns-query"
	if clientID != "" {
		serverURL += "/" + clientID
	}
	body := buildDoHMobileConfig(host, serverURL)
	w.Header().Set("Content-Type", "application/x-apple-aspen-config")
	w.Header().Set("Content-Disposition", `attachment; filename="doh.mobileconfig"`)
	_, _ = w.Write(body)
}

// normalizeProfileHost validates a profile hostname/IP and returns it in URL
// form (bare IPv6 gains brackets). Anything that could escape the ServerURL
// — schemes, paths, ports, userinfo, spaces — is rejected.
func normalizeProfileHost(host string) (string, error) {
	if host == "" {
		return "", fmt.Errorf("host is required")
	}
	if strings.ContainsAny(host, "/?#@ ") || strings.Contains(host, "://") {
		return "", fmt.Errorf("invalid host (hostname or IP only, no scheme/path/port)")
	}
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		if ip.To4() == nil {
			return "[" + ip.String() + "]", nil
		}
		return ip.String(), nil
	}
	if len(host) > 253 {
		return "", fmt.Errorf("invalid host (too long)")
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid host (bad hostname)")
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' {
				continue
			}
			return "", fmt.Errorf("invalid host (bad hostname)")
		}
	}
	return host, nil
}

// profileUUID mints a random v4 UUID for profile identifiers.
func profileUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("secure UUID generation failed: %v", err))
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%08X-%04X-%04X-%04X-%012X", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func profileEsc(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// buildDoHMobileConfig renders the DNSSettings profile plist. Values are
// XML-escaped; UUIDs are fresh per download like AdGuard Home's.
func buildDoHMobileConfig(host, serverURL string) []byte {
	display := host + " DoH"
	return []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadDescription</key>
	<string>Adds BlipDNS DoH to iOS 14 / macOS Big Sur and newer</string>
	<key>PayloadDisplayName</key>
	<string>%s</string>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadScope</key>
	<string>System</string>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>DNSSettings</key>
			<dict>
				<key>DNSProtocol</key>
				<string>HTTPS</string>
				<key>ServerURL</key>
				<string>%s</string>
			</dict>
			<key>OnDemandEnabled</key>
			<integer>1</integer>
			<key>OnDemandRules</key>
			<array>
				<dict>
					<key>Action</key>
					<string>Connect</string>
				</dict>
			</array>
			<key>PayloadType</key>
			<string>com.apple.dnsSettings.managed</string>
			<key>PayloadIdentifier</key>
			<string>com.apple.dnsSettings.managed.%s</string>
			<key>PayloadDisplayName</key>
			<string>%s</string>
			<key>PayloadDescription</key>
			<string>Configures device to use BlipDNS over HTTPS</string>
			<key>PayloadUUID</key>
			<string>%s</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>
	</array>
	<key>PayloadIdentifier</key>
	<string>%s</string>
	<key>PayloadUUID</key>
	<string>%s</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
	<key>PayloadRemovalDisallowed</key>
	<false/>
</dict>
</plist>
`, profileEsc(display), profileEsc(serverURL),
		profileUUID(), profileEsc(display), profileUUID(),
		profileUUID(), profileUUID()))
}
