package server

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/andras-tkcs/peek/internal/db"
	"github.com/andras-tkcs/peek/internal/objectstore"
	webui "github.com/andras-tkcs/peek/internal/web"
)

const (
	viewTokenTTL  = 1 * time.Hour
	sessionTTL    = 7 * 24 * time.Hour
	visitorCookie = "hn_vid"
	nameCookie    = "hn_name"
)

type Config struct {
	Addr      string
	DataDir   string
	BaseURL   string
	Secret    string
	MaxUpload int64

	Storage                string
	S3Endpoint             string
	S3Bucket               string
	S3Region               string
	S3AccessKey            string
	S3SecretKey            string
	S3AllowPrivateEndpoint bool
	OIDCAllowPrivateIssuer bool

	MaxTotalSize  int64
	RetentionDays int

	TrustedProxy bool
	// TrustedProxyCIDRs lists the proxies allowed to set X-Forwarded-For when
	// TrustedProxy is on. Empty means DefaultTrustedProxyCIDRs.
	TrustedProxyCIDRs []netip.Prefix

	Groups GroupChecker
}

type Server struct {
	store    *db.Store
	secret   string
	baseURL  string
	dataDir  string
	storage  objectstore.Storage
	renderer *webui.Renderer
	secure   bool

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	loginLimiter    *limiter
	commentLimiter  *limiter
	uploadLimiter   *limiter
	passwordLimiter *limiter
	globalLimiter   *limiter
	cliLoginLimiter *limiter
	apiKeyLimiter   *limiter

	pagePasswordFailLimiter *limiter
	accountLoginLimiter     *limiter

	trustedProxy             bool
	trustedProxyCIDRs        []netip.Prefix
	warnedUntrustedForwarder atomic.Bool
	s3AllowPrivateEndpoint   bool
	oidcAllowPrivateIssuer   bool
	visitQueue               chan visitEvent
	groups                   GroupChecker
}

func New(cfg Config) (*Server, error) {
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return nil, err
	}
	if cfg.Storage == "s3" {
		if cfg.S3Bucket == "" || cfg.S3Endpoint == "" {
			return nil, errors.New("s3 storage requires --s3-bucket and --s3-endpoint (or set via dashboard after first run)")
		}
	} else {
		cfg.Storage = "file"
	}

	secret := cfg.Secret
	if secret == "" {
		var err error
		secret, err = loadOrCreateSecret(filepath.Join(cfg.DataDir, "secret.key"))
		if err != nil {
			return nil, err
		}
	}
	store, err := db.Open(filepath.Join(cfg.DataDir, "peek.db"))
	if err != nil {
		return nil, err
	}
	closeStoreOnError := true
	defer func() {
		if closeStoreOnError {
			_ = store.Close()
		}
	}()

	baseURL := strings.TrimRight(cfg.BaseURL, "/")
	startupCtx := context.Background()
	if _, err := bootstrapSetup(startupCtx, store, cfg.DataDir, baseURL); err != nil {
		return nil, err
	}

	s3Defaults := map[string]string{
		"storage":       cfg.Storage,
		"s3_endpoint":   cfg.S3Endpoint,
		"s3_bucket":     cfg.S3Bucket,
		"s3_region":     cfg.S3Region,
		"s3_access_key": cfg.S3AccessKey,
		"s3_secret_key": cfg.S3SecretKey,
	}
	if err := initDefaultSettings(startupCtx, store, secret, cfg.MaxUpload, cfg.MaxTotalSize, cfg.RetentionDays, s3Defaults); err != nil {
		return nil, err
	}

	renderer, err := webui.NewRenderer()
	if err != nil {
		return nil, err
	}

	storageBackend, _ := store.GetSetting(startupCtx, "storage")
	if storageBackend == "" {
		storageBackend = cfg.Storage
	}

	var st objectstore.Storage
	if storageBackend == "s3" {
		if endpoint, err := store.GetSetting(startupCtx, "s3_endpoint"); err == nil && endpoint != "" {
			if err := objectstore.ValidateS3Endpoint(endpoint, cfg.S3AllowPrivateEndpoint); err != nil {
				return nil, err
			}
		}
		st = objectstore.NewS3Storage(cfg.S3AllowPrivateEndpoint, func(key string) string {
			return decryptedStoreSetting(context.Background(), store, secret, key)
		})
		slog.Info("storage backend: s3 (config managed via settings API / dashboard)")
	} else {
		uploadsDir := filepath.Join(cfg.DataDir, "uploads")
		if err := os.MkdirAll(uploadsDir, 0o755); err != nil {
			return nil, err
		}
		st = &objectstore.FileStorage{Dir: uploadsDir}
		slog.Info("storage backend: file", "dir", uploadsDir)
	}

	secure := strings.HasPrefix(baseURL, "https://")
	if !secure && !isLocalBaseURL(baseURL) {
		slog.Warn("base URL is not https — tokens and cookies sent in clear. Use a TLS reverse proxy.", "base_url", baseURL)
	}

	cidrs := cfg.TrustedProxyCIDRs
	if cfg.TrustedProxy && len(cidrs) == 0 {
		cidrs = defaultTrustedProxyPrefixes()
	}
	if cfg.TrustedProxy {
		names := make([]string, len(cidrs))
		for i, p := range cidrs {
			names[i] = p.String()
		}
		slog.Info("trusted proxy enabled", "cidrs", names)
	}

	ctx, cancel := context.WithCancel(context.Background())
	srv := &Server{
		store:                   store,
		secret:                  secret,
		baseURL:                 baseURL,
		dataDir:                 cfg.DataDir,
		storage:                 st,
		renderer:                renderer,
		secure:                  secure,
		ctx:                     ctx,
		cancel:                  cancel,
		loginLimiter:            newLimiter(10, time.Minute),
		commentLimiter:          newLimiter(30, time.Minute),
		uploadLimiter:           newLimiter(20, time.Minute),
		passwordLimiter:         newLimiter(10, time.Minute),
		globalLimiter:           newLimiter(300, time.Minute),
		cliLoginLimiter:         newLimiter(120, time.Minute),
		apiKeyLimiter:           newLimiter(10, time.Minute),
		pagePasswordFailLimiter: newLimiter(pagePasswordFailureMax, pagePasswordFailureWindow),
		accountLoginLimiter:     newLimiter(accountLoginFailureMax, accountLoginFailureWindow),
		trustedProxy:            cfg.TrustedProxy,
		trustedProxyCIDRs:       cidrs,
		s3AllowPrivateEndpoint:  cfg.S3AllowPrivateEndpoint,
		oidcAllowPrivateIssuer:  cfg.OIDCAllowPrivateIssuer,
		visitQueue:              make(chan visitEvent, 256),
	}

	if cfg.Groups != nil {
		srv.groups = cfg.Groups
	}

	if !cfg.TrustedProxy && !isLocalBaseURL(baseURL) {
		slog.Warn("trusted-proxy not set — X-Forwarded-For will be ignored. Enable if behind a reverse proxy.")
	}

	srv.wg.Add(2)
	go func() {
		defer srv.wg.Done()
		srv.startRetentionCleanup(ctx)
	}()
	go func() {
		defer srv.wg.Done()
		srv.startVisitWorker(ctx)
	}()

	closeStoreOnError = false
	return srv, nil
}
