package objectstore

import (
	"context"
	"testing"
)

func TestValidateS3EndpointRejectsMalformedAndPrivateHosts(t *testing.T) {
	for _, tc := range []struct{ name, endpoint string }{
		{"unparsable", "http://[::1"},
		{"missing host", "https:///path"},
		{"resolves to loopback", "https://localhost:9000"},
		{"metadata IP", "https://169.254.169.254"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateS3Endpoint(tc.endpoint, false); err == nil {
				t.Fatalf("ValidateS3Endpoint(%q) = nil", tc.endpoint)
			}
		})
	}
}

func TestSafeS3DialContextErrors(t *testing.T) {
	ctx := context.Background()
	dial := safeS3DialContext(true)
	if _, err := dial(ctx, "tcp", "no-port"); err == nil {
		t.Fatal("bad address: expected error")
	}
	if _, err := dial(ctx, "tcp", "nonexistent.invalid:80"); err == nil {
		t.Fatal("unresolvable host: expected error")
	}
	if _, err := dial(ctx, "tcp6", "127.0.0.1:1"); err == nil {
		t.Fatal("tcp6 with IPv4 address: expected error")
	}
	if _, err := dial(ctx, "tcp4", "[::1]:1"); err == nil {
		t.Fatal("tcp4 with IPv6 address: expected error")
	}
}
