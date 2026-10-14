package version

import (
	"strings"
	"testing"
)

func TestString(t *testing.T) {
	got := String()
	for _, part := range []string{Version, Commit, BuildDate} {
		if !strings.Contains(got, part) {
			t.Fatalf("String() = %q, missing %q", got, part)
		}
	}
}
