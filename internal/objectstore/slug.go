package objectstore

import (
	"errors"
	"fmt"
	"strings"
)

var ErrInvalidSlug = errors.New("invalid object slug")

const versionKeyPrefix = "versions/"

func objectName(key string) (string, error) {
	if !validObjectKey(key) {
		return "", fmt.Errorf("%w: %q", ErrInvalidSlug, key)
	}
	return key + ".html", nil
}

// validObjectKey accepts a plain slug or versions/<slug>/<16 lowercase hex>.
func validObjectKey(key string) bool {
	if validObjectSlug(key) {
		return true
	}
	rest, ok := strings.CutPrefix(key, versionKeyPrefix)
	if !ok {
		return false
	}
	slug, suffix, ok := strings.Cut(rest, "/")
	if !ok || !validObjectSlug(slug) || len(suffix) != 16 {
		return false
	}
	for _, r := range suffix {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

func validObjectSlug(slug string) bool {
	if slug == "" {
		return false
	}
	for _, r := range slug {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_':
		default:
			return false
		}
	}
	return true
}
