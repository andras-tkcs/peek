package server

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func mustPrefixes(t *testing.T, s string) []netip.Prefix {
	t.Helper()
	p, err := ParseTrustedProxyCIDRs(s)
	if err != nil {
		t.Fatalf("ParseTrustedProxyCIDRs(%q): %v", s, err)
	}
	return p
}

func TestClientIPRightmostUntrustedHop(t *testing.T) {
	s := &Server{trustedProxy: true, trustedProxyCIDRs: mustPrefixes(t, "127.0.0.0/8,::1/128,10.0.0.0/8")}
	tests := []struct {
		name   string
		remote string
		xff    []string
		want   string
	}{
		{"spoofed left entry", "127.0.0.1:5000", []string{"198.51.100.7, 203.0.113.10"}, "203.0.113.10"},
		{"trusted hop on the right", "127.0.0.1:5000", []string{"198.51.100.7, 203.0.113.10, 10.0.0.1"}, "203.0.113.10"},
		{"untrusted peer", "192.0.2.5:5000", []string{"203.0.113.10"}, "192.0.2.5"},
		{"all hops trusted", "127.0.0.1:5000", []string{"10.0.0.2, 10.0.0.1"}, "10.0.0.2"},
		{"garbage on the left", "127.0.0.1:5000", []string{"garbage, 203.0.113.10"}, "203.0.113.10"},
		{"garbage on the right", "127.0.0.1:5000", []string{"203.0.113.10, garbage"}, "127.0.0.1"},
		{"two headers", "127.0.0.1:5000", []string{"198.51.100.7", "203.0.113.10"}, "203.0.113.10"},
		{"ipv6", "[::1]:5000", []string{"2001:db8::1"}, "2001:db8::1"},
		{"v4-mapped", "127.0.0.1:5000", []string{"::ffff:203.0.113.10"}, "203.0.113.10"},
		{"with port", "127.0.0.1:5000", []string{"203.0.113.10:4711"}, "203.0.113.10"},
		{"no header", "127.0.0.1:5000", nil, "127.0.0.1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tc.remote
			for _, v := range tc.xff {
				req.Header.Add("X-Forwarded-For", v)
			}
			if got := s.clientIP(req); got != tc.want {
				t.Fatalf("clientIP = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestClientIPIgnoresForwardedForWithoutTrustedProxy(t *testing.T) {
	s := &Server{trustedProxyCIDRs: mustPrefixes(t, DefaultTrustedProxyCIDRs)}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:5000"
	req.Header.Set("X-Forwarded-For", "203.0.113.10")
	if got := s.clientIP(req); got != "127.0.0.1" {
		t.Fatalf("clientIP = %q, want 127.0.0.1", got)
	}
}

func TestClientIPWarnsOnceForUntrustedForwarder(t *testing.T) {
	s := &Server{trustedProxy: true, trustedProxyCIDRs: mustPrefixes(t, DefaultTrustedProxyCIDRs)}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.0.2.5:5000"
	req.Header.Set("X-Forwarded-For", "203.0.113.10")
	s.clientIP(req)
	if !s.warnedUntrustedForwarder.Load() {
		t.Fatal("expected the untrusted forwarder warning flag to be set")
	}
	s.clientIP(req)
}

func TestParseTrustedProxyCIDRs(t *testing.T) {
	got, err := ParseTrustedProxyCIDRs("127.0.0.0/8, ::1/128,,192.0.2.7")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[2].String() != "192.0.2.7/32" {
		t.Fatalf("got %v", got)
	}
	got, err = ParseTrustedProxyCIDRs("10.0.0.1/8")
	if err != nil || len(got) != 1 || got[0].String() != "10.0.0.0/8" {
		t.Fatalf("masked: got %v, err %v", got, err)
	}
	if _, err := ParseTrustedProxyCIDRs("nope"); err == nil || err.Error() != `invalid trusted proxy CIDR "nope"` {
		t.Fatalf("err = %v", err)
	}
	got, err = ParseTrustedProxyCIDRs("")
	if err != nil || len(got) != 0 {
		t.Fatalf("empty: got %v, err %v", got, err)
	}
	if _, err := ParseTrustedProxyCIDRs(DefaultTrustedProxyCIDRs); err != nil {
		t.Fatal(err)
	}
}

func TestRateLimitKeyForIP(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.10":         "203.0.113.10",
		"2001:db8:1:2:3:4:5:6": "2001:db8:1:2::/64",
		"":                     "",
		"not-an-ip":            "not-an-ip",
	} {
		if got := rateLimitKeyForIP(in); got != want {
			t.Errorf("rateLimitKeyForIP(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestClientIPCovParseTrustedProxyCIDRsEdgeCases(t *testing.T) {
	got, err := ParseTrustedProxyCIDRs("::ffff:10.0.0.0/104, ::ffff:192.0.2.9")
	if err != nil || len(got) != 2 || got[0].String() != "10.0.0.0/8" || got[1].String() != "192.0.2.9/32" {
		t.Fatalf("got %v, err %v", got, err)
	}
	for _, bad := range []string{"10.0.0.0/33", "::ffff:10.0.0.0/64", "10.0.0.0/x"} {
		if _, err := ParseTrustedProxyCIDRs(bad); err == nil || err.Error() != `invalid trusted proxy CIDR "`+bad+`"` {
			t.Errorf("ParseTrustedProxyCIDRs(%q) err = %v", bad, err)
		}
	}
}

func TestClientIPCovAddressForms(t *testing.T) {
	plain := &Server{}
	proxied := &Server{trustedProxy: true, trustedProxyCIDRs: mustPrefixes(t, DefaultTrustedProxyCIDRs)}
	tests := []struct {
		name   string
		s      *Server
		remote string
		xff    string
		want   string
	}{
		{"bare ipv4 remote", plain, "192.0.2.1", "", "192.0.2.1"},
		{"bracketed ipv6 remote without port", plain, "[2001:db8::1]", "", "2001:db8::1"},
		{"ipv6 remote with zone", plain, "[fe80::1%eth0]:80", "", "fe80::1"},
		{"v4-mapped remote", plain, "[::ffff:192.0.2.1]:80", "", "192.0.2.1"},
		{"unparsable remote with port", plain, "gateway:8080", "", "gateway"},
		{"unparsable remote without port", plain, "garbage", "", "garbage"},
		{"unparsable bracketed remote", plain, "[bad]:80", "", "bad"},
		{"bracketed forwarded hop", proxied, "127.0.0.1:1", "[2001:db8::7]", "2001:db8::7"},
		{"bracketed forwarded hop with port", proxied, "127.0.0.1:1", "[2001:db8::7]:443", "2001:db8::7"},
		{"forwarded hop with spaces", proxied, "127.0.0.1:1", "  203.0.113.4  ", "203.0.113.4"},
		{"bare ipv4 trusted peer", proxied, "127.0.0.1", "203.0.113.4", "203.0.113.4"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tc.remote
			if tc.xff != "" {
				req.Header.Set("X-Forwarded-For", tc.xff)
			}
			if got := tc.s.clientIP(req); got != tc.want {
				t.Fatalf("clientIP = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestClientIPCovRateLimitKeyGroupsIPv6(t *testing.T) {
	s := &Server{}
	a := httptest.NewRequest(http.MethodGet, "/", nil)
	a.RemoteAddr = "[2001:db8:1:2:aaaa::1]:80"
	b := httptest.NewRequest(http.MethodGet, "/", nil)
	b.RemoteAddr = "[2001:db8:1:2:bbbb::2]:80"
	if s.rateLimitKey(a) != s.rateLimitKey(b) || s.rateLimitKey(a) != "2001:db8:1:2::/64" {
		t.Fatalf("keys = %q, %q", s.rateLimitKey(a), s.rateLimitKey(b))
	}
	if got := rateLimitKeyForIP("::ffff:203.0.113.10"); got != "::ffff:203.0.113.10" {
		t.Fatalf("mapped key = %q", got)
	}
}
