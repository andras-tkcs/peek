package uploads

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const (
	slugRetries      = 5
	maxSlugLength    = 60
	slugSuffixLength = 6
	randomSlugLength = 16
	// slugAlphabet has 32 lowercase letters and digits without 0, 1, l and o,
	// so one random byte maps to one character without bias (b & 31).
	slugAlphabet = "abcdefghijkmnpqrstuvwxyz23456789"
)

func slugify(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	prevDash := true
	for i := 0; i < len(name); i++ {
		r := name[i]
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
			r += 'a' - 'A'
		case r >= '0' && r <= '9':
		default:
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
			continue
		}
		b.WriteByte(r)
		prevDash = false
	}
	s := strings.Trim(b.String(), "-")
	if len(s) > maxSlugLength {
		s = s[:maxSlugLength]
		s = strings.TrimRight(s, "-")
	}
	return s
}

// generateSlugFromName derives a link from name plus a random suffix, so a page
// cannot be found by guessing its name. Names with no slug characters get a
// fully random slug.
func generateSlugFromName(ctx context.Context, name string, store slugChecker) (string, error) {
	base := slugify(name)
	if base == "" {
		return generateRandomSlug(ctx, store)
	}
	if limit := maxSlugLength - 1 - slugSuffixLength; len(base) > limit {
		base = strings.TrimRight(base[:limit], "-")
	}
	for range slugRetries {
		suffix, err := randomSlugString(slugSuffixLength)
		if err != nil {
			return "", err
		}
		candidate := base + "-" + suffix
		exists, err := store.UploadSlugExists(ctx, candidate)
		if err != nil {
			return "", fmt.Errorf("check slug availability: %w", err)
		}
		if !exists {
			return candidate, nil
		}
	}
	return generateRandomSlug(ctx, store)
}

func generateRandomSlug(ctx context.Context, store slugChecker) (string, error) {
	for range slugRetries {
		s, err := randomSlugString(randomSlugLength)
		if err != nil {
			return "", err
		}
		exists, err := store.UploadSlugExists(ctx, s)
		if err != nil {
			return "", fmt.Errorf("check slug availability: %w", err)
		}
		if !exists {
			return s, nil
		}
	}
	return "", errors.New("slug collision after retries")
}

type slugChecker interface {
	UploadSlugExists(ctx context.Context, slug string) (bool, error)
}

// randomSlugString returns n characters from slugAlphabet using crypto/rand.
func randomSlugString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = slugAlphabet[b[i]&31]
	}
	return string(b), nil
}

func versionObjectKey(slug string) (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "versions/" + slug + "/" + hex.EncodeToString(b), nil
}
