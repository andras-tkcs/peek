package cli

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
)

var slugPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// slugPath validates a page slug against the server's slug charset and returns it
// escaped for use as one URL path segment.
func slugPath(slug string) (string, error) {
	if !slugPattern.MatchString(slug) {
		return "", fmt.Errorf("invalid slug %q: use only letters, digits, '-' and '_'", slug)
	}
	return url.PathEscape(slug), nil
}

// tokenIDPath validates a token id (positive integer) for use as a path segment.
func tokenIDPath(id string) (string, error) {
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil || n <= 0 {
		return "", fmt.Errorf("invalid token id %q: must be a positive integer", id)
	}
	return strconv.FormatInt(n, 10), nil
}
