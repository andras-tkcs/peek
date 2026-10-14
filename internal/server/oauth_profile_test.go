package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/coreos/go-oidc/v3/oidc/oidctest"
	jose "github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"
)

var oauthCovKey = func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
}()

var oauthCovOtherKey = func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
}()

// oauthCovNewIDP serves discovery, keys, a token endpoint and userinfo at its
// root. userinfo is the JSON body of /userinfo; "" answers 404.
func oauthCovNewIDP(t *testing.T, userinfo string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	var ts *httptest.Server
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		jsonOK(w, map[string]any{
			"issuer":                                ts.URL,
			"authorization_endpoint":                ts.URL + "/auth",
			"token_endpoint":                        ts.URL + "/token",
			"jwks_uri":                              ts.URL + "/keys",
			"userinfo_endpoint":                     ts.URL + "/userinfo",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{oidc.RS256},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: oauthCovKey.Public(), KeyID: "k", Algorithm: oidc.RS256, Use: "sig"}}})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if userinfo == "" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(userinfo))
	})
	ts = httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

// oauthCovIDToken signs claims (plus iss, aud and exp) as an ID token.
func oauthCovIDToken(issuer string, key *rsa.PrivateKey, claims map[string]any) *oauth2.Token {
	c := map[string]any{"iss": issuer, "aud": "cid", "exp": time.Now().Add(time.Hour).Unix(), "nonce": "n"}
	for k, v := range claims {
		c[k] = v
	}
	raw, _ := json.Marshal(c)
	return (&oauth2.Token{AccessToken: "at", TokenType: "Bearer"}).WithExtra(map[string]any{"id_token": oidctest.SignIDToken(key, "k", oidc.RS256, string(raw))})
}

func oauthCovOIDCConfig(issuer string) *oauthProviderConfig {
	return &oauthProviderConfig{authProvider: authProvider{Key: "oidc"}, ClientID: "cid", ClientSecret: "s", IssuerURL: issuer,
		Endpoint: oauth2.Endpoint{TokenURL: issuer + "/token"}}
}

func TestOAuthCovFetchProfileDispatch(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()
	empty := &oauth2.Token{AccessToken: "x"}
	if _, err := s.fetchOAuthProfile(ctx, &oauthProviderConfig{authProvider: authProvider{Key: "other"}}, empty, "n"); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("default err = %v", err)
	}
	if _, err := s.fetchOAuthProfile(ctx, &oauthProviderConfig{authProvider: authProvider{Key: "google"}}, empty, "n"); err == nil || !strings.Contains(err.Error(), "id token") {
		t.Fatalf("google err = %v", err)
	}
	if _, err := s.fetchOAuthProfile(ctx, &oauthProviderConfig{authProvider: authProvider{Key: "oidc"}, OIDCProvider: &oidc.Provider{}}, empty, "n"); err == nil || !strings.Contains(err.Error(), "id token") {
		t.Fatalf("oidc err = %v", err)
	}
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "x", http.StatusBadGateway) }))
	defer gh.Close()
	restoreGitHubURLs(t, gh.URL)
	if _, err := s.fetchOAuthProfile(ctx, testGitHubProviderConfig(), empty, "n"); err == nil || !strings.Contains(err.Error(), "github user status 502") {
		t.Fatalf("github err = %v", err)
	}
}

func TestOAuthCovFetchGoogleProfileFailures(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()
	p := &oauthProviderConfig{authProvider: authProvider{Key: "google"}, ClientID: "cid"}
	idp := oauthCovNewIDP(t, "")
	restoreGoogleIssuerURL(t, idp.URL)

	if _, err := s.fetchGoogleProfile(ctx, p, &oauth2.Token{}, "n"); err == nil || !strings.Contains(err.Error(), "missing id token") {
		t.Fatalf("missing token err = %v", err)
	}
	if _, err := s.fetchGoogleProfile(ctx, p, oauthCovIDToken(idp.URL, oauthCovOtherKey, map[string]any{"sub": "g"}), "n"); err == nil {
		t.Fatal("token signed by an unknown key was accepted")
	}
	if _, err := s.fetchGoogleProfile(ctx, p, oauthCovIDToken(idp.URL, oauthCovKey, map[string]any{"sub": "g", "email_verified": "yes"}), "n"); err == nil {
		t.Fatal("malformed claims were accepted")
	}
	p2, err := s.fetchGoogleProfile(ctx, p, oauthCovIDToken(idp.URL, oauthCovKey, map[string]any{"sub": "g", "email": "U@Example.test", "email_verified": true}), "n")
	if err != nil || p2.Email != "u@example.test" || p2.Name != "U@Example.test" || !p2.EmailVerified {
		t.Fatalf("p=%+v err=%v", p2, err)
	}
	idp.Close()
	if _, err := s.fetchGoogleProfile(ctx, p, oauthCovIDToken(idp.URL, oauthCovKey, nil), "n"); err == nil {
		t.Fatal("discovery failure was not reported")
	}
}

func oauthCovGitHubServer(t *testing.T, emails string, emailsStatus int) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":42,"login":"octo","name":""}`))
	})
	mux.HandleFunc("/emails", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(emailsStatus)
		_, _ = w.Write([]byte(emails))
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	restoreGitHubURLs(t, ts.URL)
}

func TestOAuthCovFetchGitHubProfileEmails(t *testing.T) {
	s := newTestServer(t)
	tok := &oauth2.Token{AccessToken: "x", TokenType: "Bearer"}
	for _, tc := range []struct {
		name, body string
		status     int
		wantEmail  string
		wantErr    string
	}{
		{"emails failure", `[]`, http.StatusInternalServerError, "", "github email status 500"},
		{"verified non-primary", `[{"email":"A@x.test","primary":true,"verified":false},{"email":"B@x.test","verified":true}]`, 200, "b@x.test", ""},
		{"none verified", `[{"email":"a@x.test","primary":true,"verified":false}]`, 200, "", "no verified GitHub email"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oauthCovGitHubServer(t, tc.body, tc.status)
			got, err := s.fetchGitHubProfile(context.Background(), testGitHubProviderConfig(), tok)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v", err)
				}
				return
			}
			if err != nil || got.Email != tc.wantEmail || got.ProviderUserID != "42" || got.Name != "octo" {
				t.Fatalf("got=%+v err=%v", got, err)
			}
		})
	}
}

func TestOAuthCovFetchOIDCProfile(t *testing.T) {
	s := newTestServer(t)
	ctx := context.Background()
	idp := oauthCovNewIDP(t, "")
	p := oauthCovOIDCConfig(idp.URL)
	good := map[string]any{"sub": "u1", "email": "U@x.test", "email_verified": "true", "name": "Uma"}

	got, err := s.fetchOIDCProfile(ctx, p, oauthCovIDToken(idp.URL, oauthCovKey, good), "n") // discovers the provider itself
	if err != nil || got.Email != "u@x.test" || !got.EmailVerified || got.Name != "Uma" || got.ProviderUserID != idp.URL+"#u1" {
		t.Fatalf("got=%+v err=%v", got, err)
	}
	if _, err := s.fetchOIDCProfile(ctx, p, &oauth2.Token{}, "n"); err == nil || !strings.Contains(err.Error(), "missing id token") {
		t.Fatalf("missing token err = %v", err)
	}
	if _, err := s.fetchOIDCProfile(ctx, p, oauthCovIDToken(idp.URL, oauthCovOtherKey, good), "n"); err == nil {
		t.Fatal("bad signature accepted")
	}
	if _, err := s.fetchOIDCProfile(ctx, p, oauthCovIDToken(idp.URL, oauthCovKey, map[string]any{"sub": "u1", "email_verified": "maybe"}), "n"); err == nil {
		t.Fatal("malformed claims accepted")
	}
	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close()
	if _, err := s.fetchOIDCProfile(ctx, oauthCovOIDCConfig(dead.URL), oauthCovIDToken(dead.URL, oauthCovKey, good), "n"); err == nil {
		t.Fatal("discovery failure not reported")
	}
}

func TestOAuthCovFetchOIDCProfileUserInfoFallback(t *testing.T) {
	ctx := context.Background()
	s := newTestServer(t)
	t.Run("fills email and name", func(t *testing.T) {
		idp := oauthCovNewIDP(t, `{"sub":"u1","email":"Info@x.test","email_verified":true,"name":"Info Name"}`)
		got, err := s.fetchOIDCProfile(ctx, oauthCovOIDCConfig(idp.URL), oauthCovIDToken(idp.URL, oauthCovKey, map[string]any{"sub": "u1"}), "n")
		if err != nil || got.Email != "info@x.test" || !got.EmailVerified || got.Name != "Info Name" {
			t.Fatalf("got=%+v err=%v", got, err)
		}
	})
	t.Run("unusable userinfo is ignored", func(t *testing.T) {
		for name, body := range map[string]string{"missing": "", "bad json": `[1]`} {
			idp := oauthCovNewIDP(t, body)
			got, err := s.fetchOIDCProfile(ctx, oauthCovOIDCConfig(idp.URL), oauthCovIDToken(idp.URL, oauthCovKey, map[string]any{"sub": "u1"}), "n")
			if err != nil || got.Email != "" || got.Name != "user" {
				t.Fatalf("%s: got=%+v err=%v", name, got, err)
			}
		}
	})
	t.Run("subject mismatch", func(t *testing.T) {
		idp := oauthCovNewIDP(t, `{"sub":"someone-else","email":"a@x.test","email_verified":true}`)
		_, err := s.fetchOIDCProfile(ctx, oauthCovOIDCConfig(idp.URL), oauthCovIDToken(idp.URL, oauthCovKey, map[string]any{"sub": "u1"}), "n")
		if !errors.Is(err, errOIDCUserInfoSubject) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestOAuthCovFlexibleBool(t *testing.T) {
	var v struct {
		B flexibleBool `json:"b"`
	}
	for in, want := range map[string]bool{`{"b":"false"}`: false, `{"b":false}`: false, `{"b":"0"}`: false, `{"b":null}`: false, `{"b":"true"}`: true, `{"b":1}`: true} {
		v.B = !flexibleBool(want)
		if err := json.Unmarshal([]byte(in), &v); err != nil || bool(v.B) != want {
			t.Fatalf("%s: v=%v err=%v", in, v.B, err)
		}
	}
	if err := json.Unmarshal([]byte(`{"b":"maybe"}`), &v); err == nil {
		t.Fatal("invalid boolean accepted")
	}
}

func TestOAuthCovFetchOAuthJSON(t *testing.T) {
	ctx := context.Background()
	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"a":1}`)) })
	mux.HandleFunc("/bad", func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", http.StatusForbidden) })
	mux.HandleFunc("/junk", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`not json`)) })
	mux.HandleFunc("/cut", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		_, _ = w.Write([]byte(`{"a"`))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()
	var out map[string]any
	if err := fetchOAuthJSON(ctx, ts.Client(), ts.URL+"/ok", "thing", &out); err != nil || out["a"] != float64(1) {
		t.Fatalf("out=%v err=%v", out, err)
	}
	for _, tc := range []struct{ url, want string }{
		{"http://\x7f/", "invalid"},
		{ts.URL + "/bad", "thing status 403"},
		{ts.URL + "/junk", "decode thing response"},
		{ts.URL + "/cut", "read thing response"},
	} {
		if err := fetchOAuthJSON(ctx, ts.Client(), tc.url, "thing", &out); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: err = %v, want %q", tc.url, err, tc.want)
		}
	}
	closed := ts.URL
	ts.Close()
	if err := fetchOAuthJSON(ctx, http.DefaultClient, closed+"/ok", "thing", &out); err == nil {
		t.Fatal("transport error not reported")
	}
}
