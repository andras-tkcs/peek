package cli

import (
	"strings"
	"testing"
)

func TestCovStatsAndCommentsUsageErrors(t *testing.T) {
	configureTestClient(t, "http://127.0.0.1:1")
	cases := map[string]func() error{
		"stats arity":          func() error { return cmdStats(nil) },
		"stats slug":           func() error { return cmdStats([]string{"bad/slug"}) },
		"comments no value":    func() error { return cmdComments([]string{"demo", "--version"}) },
		"comments bad version": func() error { return cmdComments([]string{"demo", "--version", "0"}) },
		"comments dup slug":    func() error { return cmdComments([]string{"demo", "other"}) },
		"comments flag":        func() error { return cmdComments([]string{"demo", "--nope"}) },
		"comments no slug":     func() error { return cmdComments(nil) },
		"comments bad slug":    func() error { return cmdComments([]string{"bad/slug"}) },
	}
	for name, fn := range cases {
		t.Run(name, func(t *testing.T) {
			if err := fn(); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestCovStatsAndCommentsEnvFailures(t *testing.T) {
	t.Run("stats", func(t *testing.T) {
		covEnvFailures(t, func() error { return cmdStats([]string{"demo"}) })
	})
	t.Run("comments", func(t *testing.T) {
		covEnvFailures(t, func() error { return cmdComments([]string{"demo", "--version", "2"}) })
	})
}

func TestCovStatsPrintsRecentVisits(t *testing.T) {
	ts := covFake(t, map[string]string{"/api/uploads/demo/stats": `{"slug":"demo","name":"Demo","total_visits":3,"unique_visitors":2,"recent":[{"name":"","ip":"abc","user_agent":"ua","visited_at":0},{"name":"Ann","ip":"def","user_agent":"ua","visited_at":0}]}`}, nil)
	configureTestClient(t, ts.URL)
	out, err := captureStdout(t, func() error { return cmdStats([]string{"demo"}) })
	if err != nil || !strings.Contains(out, "(anonymous)") || !strings.Contains(out, "Ann") {
		t.Fatalf("got %q %v", out, err)
	}
}

func TestCovCommentsKindAndContextVariants(t *testing.T) {
	ts := covFake(t, map[string]string{"/api/uploads/demo/comments": `[
		{"id":1,"author":"","body":"page","version":1,"created_at":0},
		{"id":2,"author":"Ann","selector":"p.x","element_text":"hello","body":"text","version":1,"created_at":0},
		{"id":3,"author":"Bob","selector":"div.y","body":"element","version":2,"created_at":0},
		{"id":4,"author":"Cy","anchor_kind":"text","body":"empty text","version":2,"created_at":0}
	]`, "/api/uploads/empty/comments": `[]`}, nil)
	configureTestClient(t, ts.URL)
	out, err := captureStdout(t, func() error { return cmdComments([]string{"demo"}) })
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"anonymous", "“hello”", "on: div.y", "on: whole page"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in %q", want, out)
		}
	}
	out, err = captureStdout(t, func() error { return cmdComments([]string{"empty"}) })
	if err != nil || !strings.Contains(out, "no comments yet") {
		t.Fatalf("empty: %q %v", out, err)
	}
}
