// Package groups answers Google Workspace group membership questions through
// the Admin SDK Directory API.
package groups

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	DirectoryScope  = "https://www.googleapis.com/auth/admin.directory.group.member.readonly"
	DefaultBaseURL  = "https://admin.googleapis.com"
	DefaultCacheTTL = 5 * time.Minute
	maxCacheEntries = 10000
	requestTimeout  = 5 * time.Second
)

// Directory checks group membership against the Directory API and caches answers.
type Directory struct {
	client  *http.Client
	baseURL string
	ttl     time.Duration
	now     func() time.Time
	mu      sync.Mutex
	cache   map[string]cacheEntry // key: lower(group) + "|" + lower(user)
}

type cacheEntry struct {
	member  bool
	expires time.Time
}

// NewDirectory builds a Directory that authenticates as the service account in keyJSON,
// impersonating adminEmail through domain-wide delegation.
func NewDirectory(keyJSON []byte, adminEmail string, ttl time.Duration) (*Directory, error) {
	cfg, err := google.JWTConfigFromJSON(keyJSON, DirectoryScope)
	if err != nil {
		return nil, fmt.Errorf("parse google service account key: %w", err)
	}
	cfg.Subject = adminEmail
	// The per-request timeout does not cover the token fetch, so bound it here.
	client := cfg.Client(context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{Timeout: 10 * time.Second}))
	return newDirectoryWithClient(client, DefaultBaseURL, ttl, time.Now), nil
}

func newDirectoryWithClient(client *http.Client, baseURL string, ttl time.Duration, now func() time.Time) *Directory {
	return &Directory{
		client:  client,
		baseURL: strings.TrimRight(baseURL, "/"),
		ttl:     ttl,
		now:     now,
		cache:   make(map[string]cacheEntry),
	}
}

// IsMember reports whether userEmail is a direct or nested member of groupEmail.
func (d *Directory) IsMember(ctx context.Context, groupEmail, userEmail string) (bool, error) {
	group := strings.ToLower(strings.TrimSpace(groupEmail))
	user := strings.ToLower(strings.TrimSpace(userEmail))
	key := group + "|" + user

	d.mu.Lock()
	if e, ok := d.cache[key]; ok && d.now().Before(e.expires) {
		d.mu.Unlock()
		return e.member, nil
	}
	d.mu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	endpoint := d.baseURL + "/admin/directory/v1/groups/" + url.PathEscape(group) + "/hasMember/" + url.PathEscape(user)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, fmt.Errorf("directory hasMember %s: %w", group, err)
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("directory hasMember %s: %w", group, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		var body struct {
			IsMember bool `json:"isMember"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&body); err != nil {
			return false, fmt.Errorf("directory hasMember %s: decode response: %w", group, err)
		}
		d.store(key, body.IsMember)
		return body.IsMember, nil
	case http.StatusNotFound:
		d.store(key, false)
		return false, nil
	case http.StatusBadRequest:
		slog.Info("group membership lookup rejected", "group", group, "status", 400)
		d.store(key, false)
		return false, nil
	default:
		return false, fmt.Errorf("directory hasMember %s: status %d", group, resp.StatusCode)
	}
}

func (d *Directory) store(key string, member bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.cache) >= maxCacheEntries {
		now := d.now()
		for k, e := range d.cache {
			if !now.Before(e.expires) {
				delete(d.cache, k)
			}
		}
		if len(d.cache) >= maxCacheEntries {
			d.cache = make(map[string]cacheEntry)
		}
	}
	d.cache[key] = cacheEntry{member: member, expires: d.now().Add(d.ttl)}
}
