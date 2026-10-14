package objectstore

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// ValidateS3Endpoint checks that the endpoint URL is safe by default: HTTPS
// only, not pointing at private/link-local/metadata IPs. Private/dev endpoints
// such as MinIO require an explicit allowPrivateEndpoint opt-in.
func ValidateS3Endpoint(endpoint string, allowPrivateEndpoint bool) error {
	u, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("invalid endpoint URL: %w", err)
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("endpoint missing host")
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("S3 endpoint must use http or https scheme")
	}
	if u.Scheme == "http" && !allowPrivateEndpoint {
		return errors.New("S3 endpoint must use HTTPS unless private endpoints are explicitly allowed")
	}
	if allowPrivateEndpoint {
		return nil
	}

	// Resolve and check for private/metadata IPs (skip for hostnames that
	// don't resolve here; the S3 transport validates the dialed endpoint again).
	if ip := net.ParseIP(host); ip != nil {
		if isPrivateOrMetadataIP(ip) {
			return fmt.Errorf("S3 endpoint IP %s is private or link-local", ip)
		}
	} else {
		ips, err := net.LookupIP(host)
		if err == nil {
			for _, ip := range ips {
				if isPrivateOrMetadataIP(ip) {
					return fmt.Errorf("S3 endpoint %s resolves to private IP %s", host, ip)
				}
			}
		}
	}
	return nil
}

// blockedS3Prefixes are ranges never valid for a public S3 endpoint, beyond what
// netip's IsLoopback/IsPrivate/IsLinkLocal*/IsMulticast/IsUnspecified cover.
var blockedS3Prefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),          // "this network"
	netip.MustParsePrefix("100.64.0.0/10"),      // CGNAT, incl. Alibaba Cloud metadata 100.100.100.200
	netip.MustParsePrefix("169.254.169.254/32"), // cloud metadata (also link-local)
	netip.MustParsePrefix("192.0.0.0/24"),       // IETF protocol assignments
	netip.MustParsePrefix("198.18.0.0/15"),      // benchmarking
	netip.MustParsePrefix("224.0.0.0/4"),        // IPv4 multicast
	netip.MustParsePrefix("240.0.0.0/4"),        // reserved, incl. 255.255.255.255
	netip.MustParsePrefix("::/96"),              // IPv4-compatible IPv6 (deprecated)
	netip.MustParsePrefix("64:ff9b::/96"),       // NAT64 well-known prefix
	netip.MustParsePrefix("64:ff9b:1::/48"),     // NAT64 local-use prefix
	netip.MustParsePrefix("2001::/32"),          // Teredo
	netip.MustParsePrefix("2002::/16"),          // 6to4
	netip.MustParsePrefix("fc00::/7"),           // unique local (incl. AWS fd00:ec2::254)
	netip.MustParsePrefix("fec0::/10"),          // deprecated site-local
	netip.MustParsePrefix("ff00::/8"),           // IPv6 multicast
}

// isPrivateOrMetadataIP reports whether ip must not be used as an S3 endpoint
// address unless private endpoints are explicitly allowed.
func isPrivateOrMetadataIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	addr = addr.Unmap()
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() || addr.IsInterfaceLocalMulticast() ||
		addr.IsMulticast() || addr.IsUnspecified() {
		return true
	}
	for _, p := range blockedS3Prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

var s3BucketPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

// ValidateS3Bucket accepts DNS-compatible bucket names (AWS, R2 and MinIO rules),
// so a bucket can never inject path segments, queries or fragments into object URLs.
func ValidateS3Bucket(bucket string) error {
	if !s3BucketPattern.MatchString(bucket) || strings.Contains(bucket, "..") || net.ParseIP(bucket) != nil {
		return errors.New("S3 bucket must be 3-63 lowercase letters, digits, dots or hyphens, start and end with a letter or digit, and not be an IP address")
	}
	return nil
}

func newS3HTTPClient(allowPrivateEndpoint bool) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = safeS3DialContext(allowPrivateEndpoint)
	return &http.Client{Timeout: 30 * time.Second, Transport: transport}
}

func safeS3DialContext(allowPrivateEndpoint bool) func(context.Context, string, string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("S3 endpoint %s resolved to no IPs", host)
		}
		if !allowPrivateEndpoint {
			for _, ip := range ips {
				if isPrivateOrMetadataIP(ip.IP) {
					return nil, fmt.Errorf("S3 endpoint %s resolved to private or link-local IP %s", host, ip.IP)
				}
			}
		}
		for _, ip := range ips {
			if network == "tcp4" && ip.IP.To4() == nil {
				continue
			}
			if network == "tcp6" && ip.IP.To4() != nil {
				continue
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(ip.IP.String(), port))
		}
		return nil, fmt.Errorf("S3 endpoint %s has no address for %s", host, network)
	}
}
