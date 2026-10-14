package cli

import "testing"

func TestValidateBrowserURL(t *testing.T) {
	tests := []struct {
		host, raw string
		ok        bool
	}{
		{"https://peek.example.com", "https://peek.example.com/cli-login", true},
		{"https://peek.example.com", "https://PEEK.example.com:443/cli-login", true},
		{"http://127.0.0.1:7700", "http://127.0.0.1:7700/cli-login", true},
		{"https://peek.example.com", "", false},
		{"https://peek.example.com", "-https://peek.example.com/x", false},
		{"https://peek.example.com", "file:///etc/passwd", false},
		{"https://peek.example.com", "smb://peek.example.com/share", false},
		{"https://peek.example.com", "javascript:alert(1)", false},
		{"https://peek.example.com", "http://peek.example.com/x", false},
		{"https://peek.example.com", "https://peek.example.com:8443/x", false},
		{"https://peek.example.com", "https://evil.example/x", false},
		{"https://peek.example.com", "https://user:pw@peek.example.com/x", false},
		{"https://peek.example.com", "https://peek.example.com/a b", false},
		{"https://peek.example.com", "https://peek.example.com/\nx", false},
		{"https://peek.example.com", "https:peek.example.com", false},
		{"https://peek.example.com", "https://[::1", false},
		{"https://peek.example.com", "https://peek.example.com/x", true},
		{"://bad", "https://peek.example.com/x", false},
	}
	for _, tt := range tests {
		err := validateBrowserURL(tt.host, tt.raw)
		if (err == nil) != tt.ok {
			t.Errorf("validateBrowserURL(%q, %q) = %v, want ok=%v", tt.host, tt.raw, err, tt.ok)
		}
	}
}

func TestPlainHTTPWarning(t *testing.T) {
	for _, h := range []string{"http://peek.internal:7700", "http://10.0.0.5"} {
		if plainHTTPWarning(h) == "" {
			t.Errorf("no warning for %s", h)
		}
	}
	for _, h := range []string{"https://peek.example.com", "http://localhost:7700", "http://127.0.0.1:7700", "http://[::1]:7700", "http://app.localhost", "://bad"} {
		if w := plainHTTPWarning(h); w != "" {
			t.Errorf("unexpected warning for %s: %s", h, w)
		}
	}
}

func TestOpenBrowserRefusesNonHTTPURLs(t *testing.T) {
	for _, u := range []string{"file:///etc/passwd", "-x"} {
		if err := openBrowser(u); err == nil {
			t.Errorf("openBrowser(%q) = nil, want error", u)
		}
	}
}
