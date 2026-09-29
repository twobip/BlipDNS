package control

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// Adopt-bundle: one opaque paste carrying everything the controller needs to
// adopt an instance (id, management URL, one-time code). blipd writes it to
// the 0600 adopt-code file; the dashboard, setup wizard and blipctl accept
// it anywhere a claim code goes. A bare code (no prefix) still works as
// before, so old files and old docs stay valid.
const adoptBundlePrefix = "blip1_"

// AdoptBundle is the decoded form of an adopt bundle.
type AdoptBundle struct {
	ID   string `json:"id,omitempty"`
	URL  string `json:"url"`
	Code string `json:"code"`
}

// MakeAdoptBundle encodes id + management URL + one-time code as a single
// opaque token. Empty id is allowed (the controller falls back to a typed
// name); url and code are required.
func MakeAdoptBundle(id, mgmtURL, code string) (string, error) {
	b := AdoptBundle{ID: id, URL: mgmtURL, Code: code}
	if strings.TrimSpace(code) == "" {
		return "", fmt.Errorf("control: adopt bundle requires a code")
	}
	if err := checkBundleURL(mgmtURL); err != nil {
		return "", err
	}
	raw, err := json.Marshal(struct {
		V int `json:"v"`
		AdoptBundle
	}{V: 1, AdoptBundle: b})
	if err != nil {
		return "", err
	}
	return adoptBundlePrefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

// ParseAdoptBundle decodes an adopt bundle. It reports false (no error) for
// anything without the bundle prefix — callers treat that input as a legacy
// bare claim code.
func ParseAdoptBundle(s string) (AdoptBundle, bool) {
	var b AdoptBundle
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, adoptBundlePrefix) {
		return b, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, adoptBundlePrefix))
	if err != nil {
		return b, false
	}
	var doc struct {
		V int `json:"v"`
		AdoptBundle
	}
	// ponytail: strict JSON would reject forward-compatible bundles with
	// extra keys; encoding/json ignores unknown fields by default, which is
	// exactly the tolerance a versioned envelope needs.
	if err := json.Unmarshal(raw, &doc); err != nil || doc.V != 1 {
		return b, false
	}
	b = doc.AdoptBundle
	if strings.TrimSpace(b.Code) == "" || checkBundleURL(b.URL) != nil {
		return AdoptBundle{}, false
	}
	return b, true
}

func checkBundleURL(mgmtURL string) error {
	u, err := url.Parse(strings.TrimSpace(mgmtURL))
	if err != nil {
		return fmt.Errorf("control: bad adopt bundle url: %v", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("control: adopt bundle url scheme must be http or https")
	}
	if u.Host == "" || u.Hostname() == "" {
		return fmt.Errorf("control: adopt bundle url host required")
	}
	return nil
}
