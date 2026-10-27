package cli

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestProvisionerUsageErrors(t *testing.T) {
	var hits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer ts.Close()
	configureTestClient(t, ts.URL)
	cases := map[string][]string{
		"none":              {},
		"unknown":           {"frob"},
		"create name value": {"create", "--name"},
		"create flag":       {"create", "--nope"},
		"create positional": {"create", "x"},
		"create no name":    {"create"},
		"list extra":        {"list", "x"},
		"revoke none":       {"revoke"},
		"revoke two":        {"revoke", "1", "2"},
		"revoke flag":       {"revoke", "--id"},
		"revoke bad id":     {"revoke", "abc"},
		"revoke zero":       {"revoke", "0"},
		"revoke path":       {"revoke", "1/../2"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			if err := cmdProvisioner(args); err == nil {
				t.Fatal("expected error")
			}
		})
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("%d requests sent for invalid input", n)
	}
	if err := cmdProvisioner(nil); err == nil || err.Error() != provisionerUsage {
		t.Fatalf("usage = %v", err)
	}
}

func TestProvisionerEnvFailures(t *testing.T) {
	for name, args := range map[string][]string{
		"create": {"create", "--name", "PF"},
		"list":   {"list"},
		"revoke": {"revoke", "7"},
	} {
		t.Run(name, func(t *testing.T) {
			covEnvFailures(t, func() error { return cmdProvisioner(args) })
		})
	}
}

func TestProvisionerCreatePrintsKey(t *testing.T) {
	ts := covFake(t, map[string]string{"/api/provisioners": `{"id":3,"name":"PF","key":"peekprov_secret"}`}, nil)
	configureTestClient(t, ts.URL)
	out, err := captureStdout(t, func() error { return cmdProvisioner([]string{"create", "--name", "PF"}) })
	want := "created provisioning key for \"PF\" (id 3):\n  peekprov_secret\nStore it now; Peek does not show it again.\n"
	if err != nil || out != want {
		t.Fatalf("out = %q, err = %v", out, err)
	}
}

func TestProvisionerListShowsNeverForUnusedKey(t *testing.T) {
	ts := covFake(t, map[string]string{"/api/provisioners": `[{"id":1,"name":"PF","hint":"abcd","created_at":1,"last_used_at":0,"accounts":2},{"id":2,"name":"Other","last_used_at":86400,"accounts":0}]`}, nil)
	configureTestClient(t, ts.URL)
	out, err := captureStdout(t, func() error { return cmdProvisioner([]string{"list"}) })
	if err != nil || !strings.Contains(out, "ID") || !strings.Contains(out, "LAST USED") || !strings.Contains(out, "never") ||
		!strings.Contains(out, "1970-01-02T00:00:00Z") {
		t.Fatalf("out = %q, err = %v", out, err)
	}
}

func TestProvisionerRevokeSendsDelete(t *testing.T) {
	var method, path string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, path = r.Method, r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"revoked":7}`))
	}))
	defer ts.Close()
	configureTestClient(t, ts.URL)
	out, err := captureStdout(t, func() error { return cmdProvisioner([]string{"revoke", "7"}) })
	if err != nil || out != "revoked provisioner 7\n" || method != http.MethodDelete || path != "/api/provisioners/7" {
		t.Fatalf("out = %q err = %v %s %s", out, err, method, path)
	}
}
