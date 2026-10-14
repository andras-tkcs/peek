package cli

import (
	"strings"
	"testing"
)

func TestCovTokenUsageErrors(t *testing.T) {
	configureTestClient(t, "http://127.0.0.1:1")
	cases := map[string][]string{
		"none":              {},
		"unknown":           {"frob"},
		"create name value": {"create", "--name"},
		"create flag":       {"create", "--nope"},
		"create positional": {"create", "x"},
		"create no name":    {"create"},
		"list extra":        {"list", "x"},
		"revoke id value":   {"revoke", "--id"},
		"revoke dup id":     {"revoke", "--id", "1", "--id", "2"},
		"revoke flag":       {"revoke", "--nope"},
		"revoke two ids":    {"revoke", "1", "2"},
		"revoke none":       {"revoke"},
		"revoke invalid id": {"revoke", "abc"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			if err := cmdToken(args); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestCovTokenEnvFailures(t *testing.T) {
	for name, args := range map[string][]string{
		"create": {"create", "--name", "ci"},
		"list":   {"list"},
		"revoke": {"revoke", "7"},
	} {
		t.Run(name, func(t *testing.T) {
			covEnvFailures(t, func() error { return cmdToken(args) })
		})
	}
}

func TestCovTokenSuccessPaths(t *testing.T) {
	ts := covFake(t, map[string]string{
		"/api/tokens": `{"token":"tok123","name":"ci","id":1,"admin":true}`,
	}, nil)
	configureTestClient(t, ts.URL)
	out, err := captureStdout(t, func() error { return cmdToken([]string{"create", "--name", "ci"}) })
	if err != nil || !strings.Contains(out, "tok123") {
		t.Fatalf("create: %q %v", out, err)
	}
	out, err = captureStdout(t, func() error { return cmdToken([]string{"revoke", "--id", "5"}) })
	if err != nil || !strings.Contains(out, "revoked token 5") {
		t.Fatalf("revoke: %q %v", out, err)
	}

	ts = covFake(t, map[string]string{
		"/api/tokens": `[{"id":1,"name":"a","admin":true},{"id":2,"name":"b","admin":false}]`,
	}, nil)
	configureTestClient(t, ts.URL)
	out, err = captureStdout(t, func() error { return cmdToken([]string{"list"}) })
	if err != nil || !strings.Contains(out, "yes") || !strings.Contains(out, "no") {
		t.Fatalf("list: %q %v", out, err)
	}
}
