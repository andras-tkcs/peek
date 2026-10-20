package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const oauthJSONBodyLimit = 1 << 20

var (
	errOIDCNonceMismatch   = errors.New("oidc nonce mismatch")
	errOIDCUserInfoSubject = errors.New("oidc userinfo subject does not match id token")
	// googleIssuerURL is Google's OIDC issuer; tests point it at a fake issuer.
	googleIssuerURL = "https://accounts.google.com"
)

type oauthProfile struct {
	Provider       string
	ProviderUserID string
	Email          string
	EmailVerified  bool
	Name           string
	// HostedDomain is Google's hd claim, set for Workspace-managed accounts.
	HostedDomain string
}

func (s *Server) fetchOAuthProfile(ctx context.Context, p *oauthProviderConfig, tok *oauth2.Token, nonce string) (*oauthProfile, error) {
	switch p.Key {
	case "google":
		return s.fetchGoogleProfile(ctx, p, tok, nonce)
	case "github":
		return s.fetchGitHubProfile(ctx, p, tok)
	case "oidc":
		return s.fetchOIDCProfile(ctx, p, tok, nonce)
	default:
		return nil, errors.New("unsupported provider")
	}
}

// oauthProviderUsesIDToken reports whether provider key returns an OIDC ID token that carries the nonce.
func oauthProviderUsesIDToken(key string) bool { return key == "google" || key == "oidc" }

// verifyIDTokenNonce checks that the ID token carries the nonce of this login.
func verifyIDTokenNonce(idToken *oidc.IDToken, nonce string) error {
	if nonce == "" || subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(nonce)) != 1 {
		return errOIDCNonceMismatch
	}
	return nil
}

func (s *Server) fetchGoogleProfile(ctx context.Context, p *oauthProviderConfig, tok *oauth2.Token, nonce string) (*oauthProfile, error) {
	rawIDToken, _ := tok.Extra("id_token").(string)
	if rawIDToken == "" {
		return nil, errors.New("missing id token")
	}
	provider, err := oidc.NewProvider(ctx, googleIssuerURL)
	if err != nil {
		return nil, err
	}
	idToken, err := provider.Verifier(&oidc.Config{ClientID: p.ClientID}).Verify(ctx, rawIDToken)
	if err != nil {
		return nil, err
	}
	if err := verifyIDTokenNonce(idToken, nonce); err != nil {
		return nil, err
	}
	var claims struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
		HD            string `json:"hd"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, err
	}
	return &oauthProfile{
		Provider:       "google",
		ProviderUserID: claims.Sub,
		Email:          normalizeOAuthEmail(claims.Email),
		EmailVerified:  claims.EmailVerified,
		Name:           displayName(claims.Name, claims.Email),
		HostedDomain:   strings.ToLower(strings.TrimSpace(claims.HD)),
	}, nil
}

func (s *Server) fetchGitHubProfile(ctx context.Context, p *oauthProviderConfig, tok *oauth2.Token) (*oauthProfile, error) {
	client := s.oauth2Config(p).Client(ctx, tok)
	var user struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
		Name  string `json:"name"`
	}
	if err := fetchOAuthJSON(ctx, client, githubUserURL, "github user", &user); err != nil {
		return nil, err
	}

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := fetchOAuthJSON(ctx, client, githubEmailsURL, "github email", &emails); err != nil {
		return nil, err
	}
	chosen := ""
	for _, e := range emails {
		if e.Primary && e.Verified {
			chosen = e.Email
			break
		}
	}
	if chosen == "" {
		for _, e := range emails {
			if e.Verified {
				chosen = e.Email
				break
			}
		}
	}
	if chosen == "" {
		return nil, errors.New("no verified GitHub email")
	}
	return &oauthProfile{
		Provider:       "github",
		ProviderUserID: strconv.FormatInt(user.ID, 10),
		Email:          normalizeOAuthEmail(chosen),
		EmailVerified:  true,
		Name:           displayName(user.Name, user.Login, chosen),
	}, nil
}

func (s *Server) fetchOIDCProfile(ctx context.Context, p *oauthProviderConfig, tok *oauth2.Token, nonce string) (*oauthProfile, error) {
	provider := p.OIDCProvider
	if provider == nil {
		var err error
		provider, err = s.oidcProvider(ctx, p.IssuerURL)
		if err != nil {
			return nil, err
		}
	}
	rawIDToken, _ := tok.Extra("id_token").(string)
	if rawIDToken == "" {
		return nil, errors.New("missing id token")
	}
	idToken, err := provider.Verifier(&oidc.Config{ClientID: p.ClientID}).Verify(ctx, rawIDToken)
	if err != nil {
		return nil, err
	}
	if err := verifyIDTokenNonce(idToken, nonce); err != nil {
		return nil, err
	}
	var claims oidcProfileClaims
	if err := idToken.Claims(&claims); err != nil {
		return nil, err
	}

	sub := strings.TrimSpace(claims.Sub)
	if sub == "" {
		return nil, errors.New("missing oidc subject")
	}
	email := normalizeOAuthEmail(claims.Email)
	emailVerified := bool(claims.EmailVerified)
	name := displayName(claims.Name, claims.PreferredUsername, email)

	if email == "" || !emailVerified || name == "user" {
		userInfo, err := provider.UserInfo(ctx, s.oauth2Config(p).TokenSource(ctx, tok))
		if err == nil {
			var info oidcProfileClaims
			if claimErr := userInfo.Claims(&info); claimErr == nil {
				// OIDC Core 5.3.2: userinfo must be about the ID token's subject.
				if strings.TrimSpace(info.Sub) != sub {
					return nil, errOIDCUserInfoSubject
				}
				// Email and email_verified always come from the same source.
				if (email == "" || !emailVerified) && normalizeOAuthEmail(info.Email) != "" {
					email = normalizeOAuthEmail(info.Email)
					emailVerified = bool(info.EmailVerified)
				}
				if name == "user" {
					name = displayName(info.Name, info.PreferredUsername, email)
				}
			}
		}
	}

	return &oauthProfile{
		Provider:       "oidc",
		ProviderUserID: strings.TrimRight(p.IssuerURL, "/") + "#" + sub,
		Email:          email,
		EmailVerified:  emailVerified,
		Name:           name,
	}, nil
}

type oidcProfileClaims struct {
	Sub               string       `json:"sub"`
	Email             string       `json:"email"`
	EmailVerified     flexibleBool `json:"email_verified"`
	Name              string       `json:"name"`
	PreferredUsername string       `json:"preferred_username"`
}

type flexibleBool bool

func (b *flexibleBool) UnmarshalJSON(data []byte) error {
	switch strings.Trim(strings.TrimSpace(string(data)), `"`) {
	case "true", "1":
		*b = true
	case "false", "0", "", "null":
		*b = false
	default:
		return fmt.Errorf("invalid boolean value %s", data)
	}
	return nil
}

func fetchOAuthJSON(ctx context.Context, client *http.Client, url, label string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, oauthJSONBodyLimit+1))
	if err != nil {
		return fmt.Errorf("read %s response: %w", label, err)
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("%s status %d", label, resp.StatusCode)
	}
	if len(body) > oauthJSONBodyLimit {
		return fmt.Errorf("%s response too large", label)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode %s response: %w", label, err)
	}
	return nil
}
