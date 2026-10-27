package server

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/privacyfence/peek/internal/backends"
	"github.com/privacyfence/peek/internal/models"
)

// backendInstanceSetting holds the id that scopes this peekd's containers. It
// is deliberately absent from settingsMeta, so the settings API cannot edit it.
const backendInstanceSetting = "backend_instance_id"

const (
	defaultBackendMemoryMB    = 256
	defaultBackendCPUMillis   = 500
	defaultBackendIdleMinutes = 15
	defaultBackendMaxRunning  = 10
)

var backendAllowedEntryPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._:/@-]*$`)

// normalizeBackendAllowedImages validates the allowed-image list and stores it
// joined with commas.
func normalizeBackendAllowedImages(value string) (string, error) {
	entries := backends.ParseAllowedImages(value)
	for _, e := range entries {
		if len(e) > 255 || !backendAllowedEntryPattern.MatchString(e) {
			return "", fmt.Errorf("backend_allowed_images entries must be registry prefixes or repositories")
		}
	}
	return strings.Join(entries, ","), nil
}

// normalizeBackendIntSetting accepts an empty value (use the default) or an
// integer in [min, max].
func normalizeBackendIntSetting(key, value string, min, max int) (string, error) {
	if value == "" {
		return "", nil
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < min || n > max {
		return "", fmt.Errorf("%s must be between %d and %d", key, min, max)
	}
	return strconv.Itoa(n), nil
}

func (s *Server) backendLimits(ctx context.Context) backends.Limits {
	return backends.Limits{
		IdleTimeout: time.Duration(s.settingInt(ctx, "backend_idle_minutes", defaultBackendIdleMinutes)) * time.Minute,
		MaxRunning:  s.settingInt(ctx, "backend_max_running", defaultBackendMaxRunning),
	}
}

func (s *Server) backendImageAllowed(ctx context.Context, ref string) bool {
	if backends.ValidateImageRef(ref) != nil {
		return false
	}
	allowed, _ := s.encryptedGetSetting(ctx, "backend_allowed_images")
	return backends.ImageAllowed(ref, backends.ParseAllowedImages(allowed))
}

// backendSpec resolves a page version's backend row, the page's environment
// variables and the runtime settings into what the manager needs to start it.
func (s *Server) backendSpec(ctx context.Context, b *models.UploadBackend) (backends.Spec, error) {
	vars, err := s.store.ListUploadBackendEnv(ctx, b.UploadID)
	if err != nil {
		return backends.Spec{}, err
	}
	env := make(map[string]string, len(vars))
	for _, v := range vars {
		val, err := decryptSecret(s.secret, v.Value)
		if err != nil || (val == "" && v.Value != "") {
			return backends.Spec{}, fmt.Errorf("decrypt backend variable %s", v.Name)
		}
		env[v.Name] = val
	}
	spec := backends.Spec{
		UploadID:    b.UploadID,
		Version:     b.Version,
		Image:       b.Image,
		Port:        b.Port,
		Env:         env,
		MemoryBytes: int64(s.settingInt(ctx, "backend_memory_mb", defaultBackendMemoryMB)) << 20,
		NanoCPUs:    int64(s.settingInt(ctx, "backend_cpu_millis", defaultBackendCPUMillis)) * 1_000_000,
	}
	server, _ := s.encryptedGetSetting(ctx, "backend_registry_server")
	if server != "" && backends.RegistryHost(b.Image) == server {
		user, _ := s.encryptedGetSetting(ctx, "backend_registry_username")
		password, _ := s.encryptedGetSetting(ctx, "backend_registry_password")
		spec.RegistryAuth = backends.RegistryAuth(user, password, server)
	}
	return spec, nil
}
