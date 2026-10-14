package cli

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// validateBrowserURL reports whether raw may be passed to the OS URL opener:
// an absolute http(s) URL on the same scheme, host and port as the configured
// Peek host, with no credentials, no leading '-', and no whitespace/control bytes.
func validateBrowserURL(host, raw string) error {
	if raw == "" {
		return errors.New("empty verification URL")
	}
	if strings.HasPrefix(raw, "-") {
		return errors.New("verification URL must not start with '-'")
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] <= 0x20 || raw[i] == 0x7f {
			return errors.New("verification URL contains whitespace or control characters")
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid verification URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("verification URL must use http or https")
	}
	if u.Opaque != "" || u.Host == "" {
		return errors.New("verification URL must be absolute")
	}
	if u.User != nil {
		return errors.New("verification URL must not contain credentials")
	}
	h, err := url.Parse(strings.TrimRight(host, "/"))
	if err != nil || originOf(u) != originOf(h) {
		return fmt.Errorf("verification URL is not on the configured host %s", originOf(h))
	}
	return nil
}

// originOf returns scheme://host:port in lower case, with the default port
// filled in for http and https.
func originOf(u *url.URL) string {
	if u == nil {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	port := u.Port()
	if port == "" {
		switch scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
	}
	return scheme + "://" + strings.ToLower(u.Hostname()) + ":" + port
}

// plainHTTPWarning returns a warning for http:// hosts that are not loopback, or "".
func plainHTTPWarning(host string) string {
	u, err := url.Parse(host)
	if err != nil || strings.ToLower(u.Scheme) != "http" {
		return ""
	}
	name := strings.ToLower(u.Hostname())
	if name == "localhost" || strings.HasSuffix(name, ".localhost") {
		return ""
	}
	if ip := net.ParseIP(name); ip != nil && ip.IsLoopback() {
		return ""
	}
	return fmt.Sprintf("warning: %s uses plain http://; your token and page passwords are sent unencrypted. Use https:// unless this host is only reachable on a trusted network.", host)
}
