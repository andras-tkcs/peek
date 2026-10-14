package uploads

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestSlugifyTruncatesLongNames(t *testing.T) {
	got := slugify(strings.Repeat("a", maxSlugLength-1) + "-b")
	if len(got) > maxSlugLength || strings.HasSuffix(got, "-") {
		t.Fatalf("slugify = %q", got)
	}
	if got := slugify(strings.Repeat("a", maxSlugLength+10)); len(got) != maxSlugLength {
		t.Fatalf("len = %d, want %d", len(got), maxSlugLength)
	}
}

func TestGenerateSlugFromNameLongNameLeavesRoomForSuffix(t *testing.T) {
	name := strings.Repeat("abcdefgh-", 10)
	slug, err := generateSlugFromName(context.Background(), name, &mockSlugChecker{existing: map[string]bool{}})
	if err != nil {
		t.Fatal(err)
	}
	if len(slug) > maxSlugLength || strings.Contains(slug, "--") {
		t.Fatalf("slug = %q (len %d)", slug, len(slug))
	}
}

func TestGenerateSlugFromNameCheckerError(t *testing.T) {
	boom := errors.New("boom")
	_, err := generateSlugFromName(context.Background(), "page", &mockSlugChecker{err: boom})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped boom", err)
	}
}

func TestGenerateRandomSlugCheckerError(t *testing.T) {
	boom := errors.New("boom")
	_, err := generateSlugFromName(context.Background(), "***", &mockSlugChecker{err: boom})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped boom", err)
	}
	_, err = generateRandomSlug(context.Background(), &mockSlugChecker{err: boom})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
}

func TestGenerateSlugFromNameFallsBackToRandomAfterCollisions(t *testing.T) {
	// The first slugRetries lookups all collide, then the random slug is free.
	checker := &mockSlugChecker{returnErrorAfter: slugRetries + 1}
	slug, err := generateSlugFromName(context.Background(), "page", checker)
	if err != nil {
		t.Fatal(err)
	}
	if len(slug) != randomSlugLength || strings.Contains(slug, "-") {
		t.Fatalf("slug = %q, want a fully random slug", slug)
	}
}

func TestVersionObjectKey(t *testing.T) {
	k, err := versionObjectKey("s")
	if err != nil || !strings.HasPrefix(k, "versions/s/") {
		t.Fatalf("key = %q err = %v", k, err)
	}
}
