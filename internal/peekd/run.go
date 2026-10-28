package peekd

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"syscall"
	"time"

	"github.com/privacyfence/peek/internal/backends"
	"github.com/privacyfence/peek/internal/groups"
	"github.com/privacyfence/peek/internal/server"
	"github.com/privacyfence/peek/internal/version"
)

type serveConfig struct {
	Addr      string
	DataDir   string
	BaseURL   string
	Secret    string
	MaxUpload int64
	// MetricsToken is a bearer token accepted on /metrics; when empty, an admin API token is required.
	MetricsToken string

	Storage                string
	S3Endpoint             string
	S3Bucket               string
	S3Region               string
	S3AccessKey            string
	S3SecretKey            string
	S3AllowPrivateEndpoint bool
	OIDCAllowPrivateIssuer bool

	MaxTotalSize      int64
	RetentionDays     int
	TrustedProxy      bool
	TrustedProxyCIDRs []netip.Prefix

	GoogleSAKeyFile     string
	GoogleAdminEmail    string
	GoogleGroupCacheTTL time.Duration

	Backends       string
	DockerHost     string
	BackendNetwork string

	Listener net.Listener // when set, runServe serves on it instead of listening on Addr (tests)
}

func Run(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "healthcheck":
			return runHealthcheck(args[1:])
		case "backup":
			return runBackup(args[1:])
		}
	}

	cfg, showVersion, err := parseServeConfig(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintf(os.Stderr, "peekd: %v\n", err)
		return 2
	}
	if showVersion {
		fmt.Println("peekd " + version.String())
		return 0
	}
	return runServe(cfg)
}

func writeServeUsage(w io.Writer, fs *flag.FlagSet) {
	fmt.Fprint(w, `Usage:
  peekd [flags]                                run the server
  peekd backup [--data <dir>] [path]           write a consistent SQLite snapshot (default <data>/peek-backup.db)
  peekd healthcheck [--addr <host:port|url>]   exit 0 when /healthz answers 200
  peekd --version                              print the version

Every flag except --version can also be set through an environment variable:
PEEK_ plus the flag name in upper case with dashes as underscores (--base-url
is PEEK_BASE_URL). PEEK_SECRET, PEEK_S3_SECRET_KEY and PEEK_METRICS_TOKEN also
accept a _FILE variant holding a file path. PEEK_LOG_LEVEL (debug, info, warn)
sets the log level and PEEK_HEALTHCHECK_ADDR the healthcheck address.

Flags:
`)
	fs.PrintDefaults()
}

func parseServeConfig(args []string) (serveConfig, bool, error) {
	fs := flag.NewFlagSet("peekd", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { writeServeUsage(fs.Output(), fs) }

	secretDefault, err := getenvSecret("PEEK_SECRET")
	if err != nil {
		return serveConfig{}, false, err
	}
	s3SecretKeyDefault, err := getenvSecret("PEEK_S3_SECRET_KEY")
	if err != nil {
		return serveConfig{}, false, err
	}
	metricsTokenDefault, err := getenvSecret("PEEK_METRICS_TOKEN")
	if err != nil {
		return serveConfig{}, false, err
	}
	maxUploadDefault, err := getenvInt64("PEEK_MAX_UPLOAD", 2<<20)
	if err != nil {
		return serveConfig{}, false, err
	}
	s3AllowPrivateEndpointDefault, err := getenvBool("PEEK_S3_ALLOW_PRIVATE_ENDPOINT")
	if err != nil {
		return serveConfig{}, false, err
	}
	oidcAllowPrivateIssuerDefault, err := getenvBool("PEEK_OIDC_ALLOW_PRIVATE_ISSUER")
	if err != nil {
		return serveConfig{}, false, err
	}
	maxTotalSizeDefault, err := getenvInt64("PEEK_MAX_TOTAL_SIZE", 0)
	if err != nil {
		return serveConfig{}, false, err
	}
	retentionDaysDefault, err := getenvInt("PEEK_RETENTION_DAYS", 0)
	if err != nil {
		return serveConfig{}, false, err
	}
	trustedProxyDefault, err := getenvBool("PEEK_TRUSTED_PROXY")
	if err != nil {
		return serveConfig{}, false, err
	}
	googleTTLDefault, err := time.ParseDuration(getenv("PEEK_GOOGLE_GROUP_CACHE_TTL", "5m"))
	if err != nil {
		return serveConfig{}, false, fmt.Errorf("invalid PEEK_GOOGLE_GROUP_CACHE_TTL: %w", err)
	}

	addr := fs.String("addr", getenv("PEEK_ADDR", ":7700"), "listen address")
	dataDir := fs.String("data", getenv("PEEK_DATA", "./data"), "data directory")
	baseURL := fs.String("base-url", getenv("PEEK_BASE_URL", "http://localhost:7700"), "public base URL")
	maxUpload := fs.Int64("max-upload", maxUploadDefault, "max upload size in bytes (per file)")
	secret := fs.String("secret", secretDefault, "server secret for HMAC signing and encryption (auto-generated if empty)")

	metricsToken := fs.String("metrics-token", metricsTokenDefault, "bearer token (at least 16 characters) accepted on /metrics; when empty, an admin API token is required (prefer PEEK_METRICS_TOKEN_FILE)")

	storageFlag := fs.String("storage", getenv("PEEK_STORAGE", "file"), "storage backend: file or s3")
	s3Endpoint := fs.String("s3-endpoint", getenv("PEEK_S3_ENDPOINT", ""), "S3-compatible endpoint URL")
	s3Bucket := fs.String("s3-bucket", getenv("PEEK_S3_BUCKET", ""), "S3 bucket name")
	s3Region := fs.String("s3-region", getenv("PEEK_S3_REGION", "us-east-1"), "S3 region")
	s3AccessKey := fs.String("s3-access-key", getenv("PEEK_S3_ACCESS_KEY", ""), "S3 access key")
	s3SecretKey := fs.String("s3-secret-key", s3SecretKeyDefault, "S3 secret key")
	s3AllowPrivateEndpoint := fs.Bool("s3-allow-private-endpoint", s3AllowPrivateEndpointDefault, "allow private/link-local S3 endpoint addresses for explicit dev deployments")
	oidcAllowPrivateIssuer := fs.Bool("oidc-allow-private-issuer", oidcAllowPrivateIssuerDefault, "allow http/private/link-local OIDC issuer URLs for explicit dev deployments")

	maxTotalSize := fs.Int64("max-total-size", maxTotalSizeDefault, "max total storage bytes across all uploads (0 = unlimited)")
	retentionDays := fs.Int("retention-days", retentionDaysDefault, "auto-delete uploads older than N days (0 = off)")
	trustedProxy := fs.Bool("trusted-proxy", trustedProxyDefault, "trust X-Forwarded-For header (set when behind a reverse proxy)")
	trustedProxyCIDRs := fs.String("trusted-proxy-cidrs", getenv("PEEK_TRUSTED_PROXY_CIDRS", server.DefaultTrustedProxyCIDRs), "comma-separated CIDRs of reverse proxies allowed to set X-Forwarded-For (used with --trusted-proxy)")
	googleSAKeyFile := fs.String("google-sa-key-file", getenv("PEEK_GOOGLE_SA_KEY_FILE", ""), "path to Google service account JSON key for group lookups")
	googleAdminEmail := fs.String("google-admin-email", getenv("PEEK_GOOGLE_ADMIN_EMAIL", ""), "Google Workspace admin user to impersonate for group lookups")
	googleGroupCacheTTL := fs.Duration("google-group-cache-ttl", googleTTLDefault, "how long Google group membership answers are cached")
	backendsFlag := fs.String("backends", getenv("PEEK_BACKENDS", "off"), "page backends: off or docker")
	dockerHost := fs.String("docker-host", getenv("PEEK_DOCKER_HOST", "unix:///var/run/docker.sock"), "Docker or Podman API address (unix:// or tcp://) used with --backends docker")
	backendNetwork := fs.String("backend-network", getenv("PEEK_BACKEND_NETWORK", "peek-backends"), "Docker network for backend containers")
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return serveConfig{}, false, err
	}
	if *showVersion {
		return serveConfig{}, true, nil
	}
	for _, w := range secretFlagWarnings(fs) {
		fmt.Fprintln(os.Stderr, w)
	}
	if *metricsToken != "" && len(*metricsToken) < 16 {
		return serveConfig{}, false, fmt.Errorf("metrics-token must be at least 16 characters")
	}
	cidrs, err := server.ParseTrustedProxyCIDRs(*trustedProxyCIDRs)
	if err != nil {
		return serveConfig{}, false, fmt.Errorf("trusted-proxy-cidrs: %w", err)
	}
	if *trustedProxy && len(cidrs) == 0 {
		return serveConfig{}, false, fmt.Errorf("trusted-proxy-cidrs must list at least one CIDR when trusted-proxy is set")
	}
	if err := validateServeConfig(*baseURL, *maxUpload, *storageFlag, *maxTotalSize, *retentionDays); err != nil {
		return serveConfig{}, false, err
	}
	if err := validateBackendConfig(*backendsFlag, *backendNetwork); err != nil {
		return serveConfig{}, false, err
	}
	if (*googleSAKeyFile == "") != (*googleAdminEmail == "") {
		return serveConfig{}, false, fmt.Errorf("PEEK_GOOGLE_SA_KEY_FILE and PEEK_GOOGLE_ADMIN_EMAIL must be set together")
	}
	if *googleGroupCacheTTL < time.Second || *googleGroupCacheTTL > time.Hour {
		return serveConfig{}, false, fmt.Errorf("google group cache ttl must be between 1s and 1h")
	}

	abs, err := filepath.Abs(*dataDir)
	if err != nil {
		return serveConfig{}, false, fmt.Errorf("data dir: %w", err)
	}
	return serveConfig{
		Addr:      *addr,
		DataDir:   abs,
		BaseURL:   *baseURL,
		Secret:    *secret,
		MaxUpload: *maxUpload,

		MetricsToken: *metricsToken,

		Storage:                *storageFlag,
		S3Endpoint:             *s3Endpoint,
		S3Bucket:               *s3Bucket,
		S3Region:               *s3Region,
		S3AccessKey:            *s3AccessKey,
		S3SecretKey:            *s3SecretKey,
		S3AllowPrivateEndpoint: *s3AllowPrivateEndpoint,
		OIDCAllowPrivateIssuer: *oidcAllowPrivateIssuer,

		MaxTotalSize:      *maxTotalSize,
		RetentionDays:     *retentionDays,
		TrustedProxy:      *trustedProxy,
		TrustedProxyCIDRs: cidrs,

		GoogleSAKeyFile:     *googleSAKeyFile,
		GoogleAdminEmail:    *googleAdminEmail,
		GoogleGroupCacheTTL: *googleGroupCacheTTL,

		Backends:       *backendsFlag,
		DockerHost:     *dockerHost,
		BackendNetwork: *backendNetwork,
	}, false, nil
}

func validateServeConfig(baseURL string, maxUpload int64, storage string, maxTotalSize int64, retentionDays int) error {
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("base-url must be an absolute http or https URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("base-url must use http or https")
	}
	if maxUpload <= 0 {
		return fmt.Errorf("max-upload must be greater than zero")
	}
	if maxTotalSize < 0 {
		return fmt.Errorf("max-total-size must be zero or greater")
	}
	if retentionDays < 0 {
		return fmt.Errorf("retention-days must be zero or greater")
	}
	if storage != "file" && storage != "s3" {
		return fmt.Errorf("storage must be file or s3")
	}
	return nil
}

var backendNetworkPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$`)

func validateBackendConfig(mode, network string) error {
	if mode != "off" && mode != "docker" {
		return fmt.Errorf("backends must be off or docker")
	}
	if !backendNetworkPattern.MatchString(network) {
		return fmt.Errorf("backend network must be a valid docker network name")
	}
	return nil
}

// newBackendRuntime builds the container runtime for --backends docker. Tests
// replace it so they need no Docker daemon.
var newBackendRuntime = func(host string) (backends.Runtime, error) {
	return backends.NewDockerRuntime(host)
}

// connectBackends builds and pings the container runtime when page backends
// are on. It returns a nil runtime when they are off.
func connectBackends(cfg serveConfig) (backends.Runtime, error) {
	if cfg.Backends != "docker" {
		return nil, nil
	}
	rt, err := newBackendRuntime(cfg.DockerHost)
	if err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err = rt.Ping(ctx)
		cancel()
	}
	if err != nil {
		return nil, fmt.Errorf("docker is not reachable at %s: %w", cfg.DockerHost, err)
	}
	slog.Info("page backends enabled", "docker_host", cfg.DockerHost, "network", cfg.BackendNetwork)
	return rt, nil
}

func runServe(cfg serveConfig) int {
	configureLogging()

	var groupChecker server.GroupChecker
	if cfg.GoogleSAKeyFile != "" {
		keyJSON, err := os.ReadFile(cfg.GoogleSAKeyFile)
		if err != nil {
			slog.Error("init", "err", fmt.Errorf("read google service account key: %w", err))
			return 1
		}
		dir, err := groups.NewDirectory(keyJSON, cfg.GoogleAdminEmail, cfg.GoogleGroupCacheTTL)
		if err != nil {
			slog.Error("init", "err", err)
			return 1
		}
		groupChecker = dir
		slog.Info("google group lookup enabled", "admin_email", cfg.GoogleAdminEmail, "cache_ttl", cfg.GoogleGroupCacheTTL)
	}

	backendRuntime, err := connectBackends(cfg)
	if err != nil {
		slog.Error("init", "err", err)
		return 1
	}

	srv, err := server.New(server.Config{
		Addr:      cfg.Addr,
		DataDir:   cfg.DataDir,
		BaseURL:   cfg.BaseURL,
		Secret:    cfg.Secret,
		MaxUpload: cfg.MaxUpload,

		MetricsToken: cfg.MetricsToken,

		Storage:                cfg.Storage,
		S3Endpoint:             cfg.S3Endpoint,
		S3Bucket:               cfg.S3Bucket,
		S3Region:               cfg.S3Region,
		S3AccessKey:            cfg.S3AccessKey,
		S3SecretKey:            cfg.S3SecretKey,
		S3AllowPrivateEndpoint: cfg.S3AllowPrivateEndpoint,
		OIDCAllowPrivateIssuer: cfg.OIDCAllowPrivateIssuer,

		MaxTotalSize:      cfg.MaxTotalSize,
		RetentionDays:     cfg.RetentionDays,
		TrustedProxy:      cfg.TrustedProxy,
		TrustedProxyCIDRs: cfg.TrustedProxyCIDRs,
		Groups:            groupChecker,

		BackendRuntime: backendRuntime,
		BackendNetwork: cfg.BackendNetwork,
	})
	if err != nil {
		slog.Error("init", "err", err)
		return 1
	}

	slog.Info("peek starting", "addr", cfg.Addr, "data", cfg.DataDir, "base_url", cfg.BaseURL, "metrics_token_set", cfg.MetricsToken != "")
	hs := &http.Server{
		Addr:         cfg.Addr,
		Handler:      srv.Handler(),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	// Live-reload streams stay open while a viewer has a page open; end them so
	// Shutdown does not wait for viewers to leave.
	hs.RegisterOnShutdown(srv.CloseEventStreams)

	serverErr := make(chan error, 1)
	go func() {
		var err error
		if cfg.Listener != nil {
			err = hs.Serve(cfg.Listener)
		} else {
			err = hs.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			serverErr <- err
			return
		}
		serverErr <- nil
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(stop)

	select {
	case err := <-serverErr:
		if err != nil {
			slog.Error("server", "err", err)
			closeServer(srv)
			return 1
		}
		closeServer(srv)
		return 0
	case sig := <-stop:
		slog.Info("shutting down", "signal", sig.String())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := hs.Shutdown(ctx); err != nil {
		slog.Error("graceful shutdown failed", "err", err)
	}
	select {
	case err := <-serverErr:
		if err != nil {
			slog.Error("server", "err", err)
		}
	case <-ctx.Done():
	}
	closeServer(srv)
	slog.Info("bye")
	return 0
}

func closeServer(srv *server.Server) {
	if err := srv.Close(); err != nil {
		slog.Error("store close", "err", err)
	}
}

func configureLogging() {
	logLevel := slog.LevelInfo
	if v := os.Getenv("PEEK_LOG_LEVEL"); v == "debug" {
		logLevel = slog.LevelDebug
	} else if v == "warn" {
		logLevel = slog.LevelWarn
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})))
}
