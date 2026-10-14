package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// oauthCovEnable configures provider key with a client id, secret and optional issuer.
func oauthCovEnable(t *testing.T, s *Server, key, issuer string) {
	t.Helper()
	ctx := context.Background()
	if err := s.store.SetSetting(ctx, "oauth_"+key+"_enabled", "true"); err != nil {
		t.Fatal(err)
	}
	if err := s.store.SetSetting(ctx, "oauth_"+key+"_client_id", "cid"); err != nil {
		t.Fatal(err)
	}
	if err := s.encryptedSetSetting(ctx, "oauth_"+key+"_client_secret", "csecret"); err != nil {
		t.Fatal(err)
	}
	if issuer != "" {
		if err := s.store.SetSetting(ctx, "oauth_"+key+"_issuer_url", issuer); err != nil {
			t.Fatal(err)
		}
	}
}

func TestOAuthCovAuthProvidersEndpoint(t *testing.T) {
	s := newTestServer(t)
	oauthCovEnable(t, s, "github", "")
	rec := httptest.NewRecorder()
	s.handleAuthProviders(rec, httptest.NewRequest(http.MethodGet, "/api/auth/providers", nil))
	var body struct {
		Providers     []authProvider `json:"providers"`
		BrowserLogin  bool           `json:"browser_login"`
		OAuthRequired bool           `json:"oauth_required"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Providers) != 1 || body.Providers[0].Key != "github" || body.BrowserLogin || !body.OAuthRequired {
		t.Fatalf("body = %+v", body)
	}
}

func TestOAuthCovProviderMetadata(t *testing.T) {
	ctx := context.Background()
	s := newTestServer(t)
	oauthCovEnable(t, s, "google", "")
	if p, err := s.oauthProviderMetadata(ctx, " Google "); err != nil || p.Key != "google" {
		t.Fatalf("p=%+v err=%v", p, err)
	}
	oauthCovEnable(t, s, "oidc", "ftp://sso.example.test")
	if _, err := s.oauthProviderMetadata(ctx, "oidc"); err == nil {
		t.Fatal("invalid OIDC issuer was accepted")
	}
	oauthCovEnable(t, s, "bogus", "")
	if _, err := s.oauthProviderMetadata(ctx, "bogus"); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("err = %v", err)
	}
}

func TestOAuthCovProviderConfig(t *testing.T) {
	ctx := context.Background()
	s := newTestServer(t)
	oauthCovEnable(t, s, "google", "")
	oauthCovEnable(t, s, "github", "")
	oauthCovEnable(t, s, "bogus", "")
	for _, key := range []string{"google", "github"} {
		p, err := s.oauthProviderConfig(ctx, key)
		if err != nil || p.Key != key || p.ClientID != "cid" || p.ClientSecret != "csecret" || len(p.Scopes) == 0 {
			t.Fatalf("%s: p=%+v err=%v", key, p, err)
		}
	}
	if _, err := s.oauthProviderConfig(ctx, "bogus"); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("bogus err = %v", err)
	}
	if _, err := s.oauthProviderConfig(ctx, "oidc"); err == nil {
		t.Fatal("unconfigured oidc accepted")
	}

	oauthCovEnable(t, s, "oidc", "")
	if _, err := s.oauthProviderConfig(ctx, "oidc"); err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("empty issuer err = %v", err)
	}
	if err := s.store.SetSetting(ctx, "oauth_oidc_issuer_url", "ftp://sso.example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.oauthProviderConfig(ctx, "oidc"); err == nil || !strings.Contains(err.Error(), "http or https") {
		t.Fatalf("bad scheme err = %v", err)
	}
	// Discovery fails against a closed port.
	s.oidcAllowPrivateIssuer = true
	if err := s.store.SetSetting(ctx, "oauth_oidc_issuer_url", "http://127.0.0.1:1/"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.oauthProviderConfig(ctx, "oidc"); err == nil {
		t.Fatal("discovery failure was not reported")
	}
}

func TestOAuthCovProviderConfigOIDCDiscovery(t *testing.T) {
	idp := oauthCovNewIDP(t, "")
	s := newTestServer(t)
	s.oidcAllowPrivateIssuer = true
	oauthCovEnable(t, s, "oidc", idp.URL+"/")
	p, err := s.oauthProviderConfig(context.Background(), "oidc")
	if err != nil {
		t.Fatal(err)
	}
	if p.IssuerURL != idp.URL || p.OIDCProvider == nil || p.Endpoint.TokenURL != idp.URL+"/token" {
		t.Fatalf("p = %+v", p)
	}
}

func TestOAuthCovNormalizeOIDCIssuerURL(t *testing.T) {
	for _, tc := range []struct {
		name, in, want string
		allowPrivate   bool
	}{
		{"parse error", "http://[::1", "invalid OIDC issuer URL", false},
		{"bad scheme", "ftp://sso.example.test", "http or https", false},
		{"http needs opt-in", "http://sso.example.test", "must use https", false},
		{"empty host", "https://", "include a host", false},
		{"user info", "https://u:p@sso.example.test", "user info", false},
		{"private ip", "https://10.0.0.1", "private or link-local", false},
		{"resolves to loopback", "https://localhost/", "resolves to private IP", false},
		{"private allowed", "http://127.0.0.1:8080/", "", true},
		{"public ip", "https://8.8.8.8/", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeOIDCIssuerURL(tc.in, tc.allowPrivate)
			if tc.want == "" {
				if err != nil || got != strings.TrimRight(tc.in, "/") {
					t.Fatalf("got %q err %v", got, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}
