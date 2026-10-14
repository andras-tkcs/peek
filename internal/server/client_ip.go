package server

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
)

// DefaultTrustedProxyCIDRs is the default --trusted-proxy-cidrs value: only a
// reverse proxy on the same host is trusted to append X-Forwarded-For.
const DefaultTrustedProxyCIDRs = "127.0.0.0/8,::1/128"

// ParseTrustedProxyCIDRs parses a comma-separated list of CIDRs or bare IPs.
// Empty items are skipped. A bare IP becomes a single-address prefix.
func ParseTrustedProxyCIDRs(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		var p netip.Prefix
		if strings.Contains(item, "/") {
			parsed, err := netip.ParsePrefix(item)
			if err != nil {
				return nil, fmt.Errorf("invalid trusted proxy CIDR %q", item)
			}
			if parsed.Addr().Is4In6() {
				if parsed.Bits() < 96 {
					return nil, fmt.Errorf("invalid trusted proxy CIDR %q", item)
				}
				parsed = netip.PrefixFrom(parsed.Addr().Unmap(), parsed.Bits()-96)
			}
			p = parsed
		} else {
			a, err := netip.ParseAddr(item)
			if err != nil {
				return nil, fmt.Errorf("invalid trusted proxy CIDR %q", item)
			}
			a = a.Unmap()
			p = netip.PrefixFrom(a, a.BitLen())
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

func defaultTrustedProxyPrefixes() []netip.Prefix {
	p, err := ParseTrustedProxyCIDRs(DefaultTrustedProxyCIDRs)
	if err != nil {
		panic(err)
	}
	return p
}

// clientIP returns the address used for visit hashes and audit logs. Without
// --trusted-proxy it is the TCP peer. With it, X-Forwarded-For is honoured only
// when the peer is a trusted proxy, and the result is the rightmost hop that is
// not itself a trusted proxy: proxies append on the right, so everything left
// of the first untrusted hop is client-controlled.
func (s *Server) clientIP(r *http.Request) string {
	peer, ok := parseRemoteAddr(r.RemoteAddr)
	if !ok {
		return legacyRemoteHost(r.RemoteAddr)
	}
	if !s.trustedProxy {
		return peer.String()
	}
	values := r.Header.Values("X-Forwarded-For")
	if len(values) == 0 {
		return peer.String()
	}
	if !s.isTrustedProxy(peer) {
		s.warnUntrustedForwarder(peer)
		return peer.String()
	}
	hops := strings.Split(strings.Join(values, ","), ",")
	client := peer
	for i := len(hops) - 1; i >= 0; i-- {
		hop, ok := parseForwardedHop(hops[i])
		if !ok {
			return client.String()
		}
		client = hop
		if !s.isTrustedProxy(hop) {
			return hop.String()
		}
	}
	return client.String()
}

func legacyRemoteHost(addr string) string {
	if i := strings.LastIndexByte(addr, ':'); i >= 0 {
		addr = addr[:i]
	}
	return strings.Trim(addr, "[]")
}

func parseRemoteAddr(addr string) (netip.Addr, bool) {
	if ap, err := netip.ParseAddrPort(addr); err == nil {
		return ap.Addr().Unmap().WithZone(""), true
	}
	if a, err := netip.ParseAddr(strings.Trim(addr, "[]")); err == nil {
		return a.Unmap().WithZone(""), true
	}
	return netip.Addr{}, false
}

func parseForwardedHop(v string) (netip.Addr, bool) {
	v = strings.TrimSpace(v)
	if a, err := netip.ParseAddr(strings.Trim(v, "[]")); err == nil {
		return a.Unmap().WithZone(""), true
	}
	if ap, err := netip.ParseAddrPort(v); err == nil {
		return ap.Addr().Unmap().WithZone(""), true
	}
	return netip.Addr{}, false
}

func (s *Server) isTrustedProxy(a netip.Addr) bool {
	for _, p := range s.trustedProxyCIDRs {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func (s *Server) warnUntrustedForwarder(peer netip.Addr) {
	if s.warnedUntrustedForwarder.CompareAndSwap(false, true) {
		slog.Warn("ignoring X-Forwarded-For from a peer outside the trusted proxy CIDRs; set PEEK_TRUSTED_PROXY_CIDRS to your reverse proxy's address", "peer", peer.String())
	}
}

// rateLimitKeyForIP groups IPv6 clients by /64, the smallest block a single
// site normally gets, so one client cannot rotate through its own addresses to
// reset limits or fill limiter maps. IPv4 and unparseable values are returned as is.
func rateLimitKeyForIP(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	a = a.Unmap()
	if !a.Is6() {
		return ip
	}
	p, err := a.WithZone("").Prefix(64)
	if err != nil {
		return ip
	}
	return p.String()
}

func (s *Server) rateLimitKey(r *http.Request) string { return rateLimitKeyForIP(s.clientIP(r)) }
