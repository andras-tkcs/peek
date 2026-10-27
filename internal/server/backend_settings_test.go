package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/privacyfence/peek/internal/backends"
	"github.com/privacyfence/peek/internal/backends/backendstest"
	"github.com/privacyfence/peek/internal/models"
	"github.com/privacyfence/peek/internal/uploadquota"
)

func TestBackendSettingsDefaults(t *testing.T) {
	s, _, _ := newBackendTestServer(t)
	ctx := context.Background()
	lim := s.backendLimits(ctx)
	if lim.IdleTimeout != 15*time.Minute || lim.MaxRunning != 10 {
		t.Fatalf("limits = %+v", lim)
	}
	if s.backendImageAllowed(ctx, "ghcr.io/acme/app:1") {
		t.Fatal("image allowed with empty allowlist")
	}
	for key, val := range map[string]string{"backend_idle_minutes": "3", "backend_max_running": "7"} {
		if err := s.encryptedSetSetting(ctx, key, val); err != nil {
			t.Fatal(err)
		}
	}
	lim = s.backendLimits(ctx)
	if lim.IdleTimeout != 3*time.Minute || lim.MaxRunning != 7 {
		t.Fatalf("limits = %+v", lim)
	}
}

func TestBackendSettingsNormalization(t *testing.T) {
	s := &Server{}
	tests := []struct {
		key, in, want, wantErr string
	}{
		{"backend_allowed_images", "", "", ""},
		{"backend_allowed_images", " ghcr.io/acme/ ,\nghcr.io/x/app ", "ghcr.io/acme/,ghcr.io/x/app", ""},
		{"backend_allowed_images", "GHCR.io/acme/", "", "backend_allowed_images entries must be registry prefixes or repositories"},
		{"backend_allowed_images", "a b", "", "backend_allowed_images entries must be registry prefixes or repositories"},
		{"backend_allowed_images", "/abs", "", "backend_allowed_images entries must be registry prefixes or repositories"},
		{"backend_allowed_images", "a" + strings.Repeat("b", 255), "", "backend_allowed_images entries must be registry prefixes or repositories"},
		{"backend_memory_mb", "", "", ""},
		{"backend_memory_mb", "16", "16", ""},
		{"backend_memory_mb", "65536", "65536", ""},
		{"backend_memory_mb", "15", "", "backend_memory_mb must be between 16 and 65536"},
		{"backend_memory_mb", "65537", "", "backend_memory_mb must be between 16 and 65536"},
		{"backend_memory_mb", "x", "", "backend_memory_mb must be between 16 and 65536"},
		{"backend_cpu_millis", "50", "50", ""},
		{"backend_cpu_millis", "64000", "64000", ""},
		{"backend_cpu_millis", "49", "", "backend_cpu_millis must be between 50 and 64000"},
		{"backend_cpu_millis", "64001", "", "backend_cpu_millis must be between 50 and 64000"},
		{"backend_idle_minutes", "1", "1", ""},
		{"backend_idle_minutes", "1440", "1440", ""},
		{"backend_idle_minutes", "0", "", "backend_idle_minutes must be between 1 and 1440"},
		{"backend_idle_minutes", "1441", "", "backend_idle_minutes must be between 1 and 1440"},
		{"backend_max_running", "1000", "1000", ""},
		{"backend_max_running", "0", "", "backend_max_running must be between 1 and 1000"},
		{"backend_max_running", "1001", "", "backend_max_running must be between 1 and 1000"},
		{"backend_registry_server", " ghcr.io ", "ghcr.io", ""},
		{"backend_registry_username", "bot", "bot", ""},
		{"backend_registry_password", "pw", "pw", ""},
	}
	for _, tt := range tests {
		got, err := s.normalizeSettingValue(tt.key, tt.in)
		if tt.wantErr != "" {
			if err == nil || err.Error() != tt.wantErr {
				t.Errorf("%s(%q) err = %v, want %q", tt.key, tt.in, err, tt.wantErr)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Errorf("%s(%q) = %q, %v; want %q", tt.key, tt.in, got, err, tt.want)
		}
	}
}

func TestBackendImageAllowedUsesAllowlist(t *testing.T) {
	s, _, _ := newBackendTestServer(t)
	ctx := context.Background()
	if err := s.encryptedSetSetting(ctx, "backend_allowed_images", "ghcr.io/acme/,docker.io/library/nginx"); err != nil {
		t.Fatal(err)
	}
	for ref, want := range map[string]bool{
		"ghcr.io/acme/app:1":        true,
		"ghcr.io/acme-evil/app":     false,
		"docker.io/library/nginx:1": true,
		"docker.io/library/nginx2":  false,
		"GHCR.io/acme/app":          false,
		"":                          false,
	} {
		if got := s.backendImageAllowed(ctx, ref); got != want {
			t.Errorf("backendImageAllowed(%q) = %v, want %v", ref, got, want)
		}
	}
}

func backendSpecFixture(t *testing.T, s *Server) *models.UploadBackend {
	t.Helper()
	ctx := context.Background()
	acct, err := s.store.CreateAccount(ctx, "owner@example.test", "owner", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.CreateUploadChecked(ctx, "page", acct.ID, 0, "page.html", 10, "public", uploadquota.Limits{}); err != nil {
		t.Fatal(err)
	}
	u, err := s.store.GetUpload(ctx, "page")
	if err != nil {
		t.Fatal(err)
	}
	b := models.UploadBackend{UploadID: u.ID, Version: 1, Image: "ghcr.io/acme/app:1", Port: 9000}
	if err := s.store.SetUploadBackend(ctx, b); err != nil {
		t.Fatal(err)
	}
	return &b
}

func TestBackendSpecDecryptsEnvAndConvertsLimits(t *testing.T) {
	s, _, _ := newBackendTestServer(t)
	ctx := context.Background()
	b := backendSpecFixture(t, s)
	enc, err := encryptSecret(s.secret, "hunter2")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.SetUploadBackendEnv(ctx, b.UploadID, "SMTP_PASSWORD", enc); err != nil {
		t.Fatal(err)
	}
	if err := s.encryptedSetSetting(ctx, "backend_memory_mb", "128"); err != nil {
		t.Fatal(err)
	}
	spec, err := s.backendSpec(ctx, b)
	if err != nil {
		t.Fatal(err)
	}
	if spec.Env["SMTP_PASSWORD"] != "hunter2" || spec.Image != b.Image || spec.Port != 9000 || spec.UploadID != b.UploadID || spec.Version != 1 {
		t.Fatalf("spec = %+v", spec)
	}
	if spec.MemoryBytes != 128<<20 || spec.NanoCPUs != 500_000_000 {
		t.Fatalf("limits = %d bytes, %d nanocpus", spec.MemoryBytes, spec.NanoCPUs)
	}
	if spec.RegistryAuth != "" {
		t.Fatalf("RegistryAuth = %q without registry settings", spec.RegistryAuth)
	}

	foreign, err := encryptSecret(strings.Repeat("cd", 32), "other")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.store.SetUploadBackendEnv(ctx, b.UploadID, "BAD", foreign); err != nil {
		t.Fatal(err)
	}
	if _, err := s.backendSpec(ctx, b); err == nil || err.Error() != "decrypt backend variable BAD" {
		t.Fatalf("err = %v, want decrypt backend variable BAD", err)
	}
}

func TestBackendSpecRegistryAuthOnlyForMatchingHost(t *testing.T) {
	s, _, _ := newBackendTestServer(t)
	ctx := context.Background()
	b := backendSpecFixture(t, s)
	for k, v := range map[string]string{
		"backend_registry_server":   "ghcr.io",
		"backend_registry_username": "bot",
		"backend_registry_password": "tok",
	} {
		if err := s.encryptedSetSetting(ctx, k, v); err != nil {
			t.Fatal(err)
		}
	}
	spec, err := s.backendSpec(ctx, b)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.URLEncoding.DecodeString(spec.RegistryAuth)
	if err != nil {
		t.Fatalf("RegistryAuth %q: %v", spec.RegistryAuth, err)
	}
	var auth map[string]string
	if err := json.Unmarshal(raw, &auth); err != nil {
		t.Fatal(err)
	}
	if auth["username"] != "bot" || auth["password"] != "tok" || auth["serveraddress"] != "ghcr.io" {
		t.Fatalf("auth = %v", auth)
	}

	other := *b
	other.Image = "docker.io/library/nginx:1"
	spec, err = s.backendSpec(ctx, &other)
	if err != nil {
		t.Fatal(err)
	}
	if spec.RegistryAuth != "" {
		t.Fatalf("RegistryAuth for other registry = %q", spec.RegistryAuth)
	}
}

func TestNewWithBackendRuntimeKeepsInstanceIDAndEnsuresNetwork(t *testing.T) {
	dir := t.TempDir()
	fake := backendstest.NewFakeRuntime()
	s1 := newBackendTestServerIn(t, dir, fake)
	id1, err := s1.store.GetSetting(context.Background(), backendInstanceSetting)
	if err != nil || len(id1) != 8 {
		t.Fatalf("instance id = %q, %v", id1, err)
	}
	if err := s1.Close(); err != nil {
		t.Fatal(err)
	}
	fake2 := backendstest.NewFakeRuntime()
	s2 := newBackendTestServerIn(t, dir, fake2)
	id2, _ := s2.store.GetSetting(context.Background(), backendInstanceSetting)
	if id2 != id1 {
		t.Fatalf("instance id changed: %q -> %q", id1, id2)
	}
	for _, f := range []*backendstest.FakeRuntime{fake, fake2} {
		f.Lock()
		nets := append([]string(nil), f.Networks...)
		f.Unlock()
		if len(nets) != 1 || nets[0] != "peek-test" {
			t.Fatalf("Networks = %v", nets)
		}
	}
	if _, ok := settingsMeta[backendInstanceSetting]; ok {
		t.Fatal("backend_instance_id must not be editable through settingsMeta")
	}
}

func TestNewFailsWhenBackendsCannotStart(t *testing.T) {
	fake := backendstest.NewFakeRuntime()
	fake.NetworkErr = http.ErrServerClosed
	_, err := New(Config{
		DataDir:        t.TempDir(),
		BaseURL:        "http://localhost:7700",
		Secret:         strings.Repeat("ab", 32),
		MaxUpload:      1 << 20,
		BackendRuntime: fake,
		BackendNetwork: "peek-test",
	})
	if err == nil || !strings.Contains(err.Error(), "start backends") {
		t.Fatalf("err = %v, want start backends", err)
	}
}

func TestServerCloseStopsRunningBackend(t *testing.T) {
	s, fake, _ := newBackendTestServer(t)
	ln := newBackendListener(t)
	if _, err := s.backends.Ensure(context.Background(), backends.Spec{UploadID: 1, Version: 1, Image: "x:1", Port: ln}); err != nil {
		t.Fatal(err)
	}
	if !s.backends.Running(1, 1) {
		t.Fatal("backend not running")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	fake.Lock()
	defer fake.Unlock()
	if len(fake.Stopped) != 1 || len(fake.Removed) == 0 {
		t.Fatalf("Stopped=%v Removed=%v", fake.Stopped, fake.Removed)
	}
}

func TestRegistryPasswordStoredEncryptedAndMasked(t *testing.T) {
	s, _, adminToken := newBackendTestServer(t)
	ctx := context.Background()
	body := strings.NewReader(`{"backend_registry_password":"s3cret","backend_memory_mb":"512"}`)
	rec := doRequest(t, s, http.MethodPut, "/api/settings", body, asBearer(adminToken), withJSON())
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /api/settings = %d: %s", rec.Code, rec.Body.String())
	}
	raw, err := s.store.GetSetting(ctx, "backend_registry_password")
	if err != nil || raw == "" || raw == "s3cret" {
		t.Fatalf("stored = %q, %v; want ciphertext", raw, err)
	}
	rec = doRequest(t, s, http.MethodGet, "/api/settings", nil, asBearer(adminToken))
	var rows []settingsRow
	if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range rows {
		got[r.Key] = r.Value
	}
	if got["backend_registry_password"] != "••••" || got["backend_memory_mb"] != "512" {
		t.Fatalf("settings = %v", got)
	}
	rec = doRequest(t, s, http.MethodPut, "/api/settings", strings.NewReader(`{"backend_memory_mb":"5"}`), asBearer(adminToken), withJSON())
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "backend_memory_mb must be between 16 and 65536") {
		t.Fatalf("out of range = %d: %s", rec.Code, rec.Body.String())
	}
}
