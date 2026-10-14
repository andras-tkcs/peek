package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/andras-tkcs/peek/internal/version"
)

var (
	oauthNow                   = time.Now
	oauthSleep                 = time.Sleep
	oauthOpenBrowser           = openBrowser
	oauthStderr      io.Writer = os.Stderr
)

func loginOAuth(cfg *Config, host string) error {
	host = strings.TrimRight(host, "/")
	var start struct {
		DeviceCode      string `json:"device_code"`
		UserCode        string `json:"user_code"`
		VerificationURL string `json:"verification_url"`
		Interval        int    `json:"interval"`
		ExpiresIn       int    `json:"expires_in"`
	}
	if err := postJSONNoAuth(host, "/api/cli/login/start", nil, &start); err != nil {
		return err
	}
	if start.Interval <= 0 {
		start.Interval = 2
	}
	if start.ExpiresIn <= 0 {
		start.ExpiresIn = 900
	}
	if err := validateBrowserURL(host, start.VerificationURL); err != nil {
		fmt.Fprintf(oauthStderr, "Peek login.\nURL:  %q\nCode: %s\n", start.VerificationURL, start.UserCode)
		fmt.Fprintf(oauthStderr, "Not opening the browser automatically: %v\nOpen the URL above yourself only if you trust it.\n", err)
	} else {
		fmt.Fprintf(oauthStderr, "Opening browser for Peek login.\nURL:  %s\nCode: %s\nType this code on that page. Never enter a code that someone else sent you.\n", start.VerificationURL, start.UserCode)
		if err := oauthOpenBrowser(start.VerificationURL); err != nil {
			fmt.Fprintln(oauthStderr, "Open the URL above to continue.")
		}
	}
	deadline := oauthNow().Add(time.Duration(start.ExpiresIn) * time.Second)
	for oauthNow().Before(deadline) {
		oauthSleep(time.Duration(start.Interval) * time.Second)
		var poll struct {
			Status string `json:"status"`
			Token  string `json:"token"`
		}
		body := map[string]string{"device_code": start.DeviceCode}
		if err := postJSONNoAuth(host, "/api/cli/login/poll", body, &poll); err != nil {
			return err
		}
		switch poll.Status {
		case "pending":
			continue
		case "approved":
			if poll.Token == "" {
				return fmt.Errorf("server approved login without a token")
			}
			cfg.Host = host
			cfg.Token = poll.Token
			if err := SaveConfig(cfg); err != nil {
				return err
			}
			fmt.Println("saved.")
			return nil
		case "denied":
			return fmt.Errorf("login denied")
		case "expired":
			return fmt.Errorf("login expired")
		case "consumed":
			return fmt.Errorf("login already consumed")
		default:
			return fmt.Errorf("unexpected login status: %s", poll.Status)
		}
	}
	return fmt.Errorf("login expired")
}

func postJSONNoAuth(host, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		var buf bytes.Buffer
		if err := json.NewEncoder(&buf).Encode(in); err != nil {
			return err
		}
		body = &buf
	}
	req, err := http.NewRequest(http.MethodPost, host+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "peek-cli/"+version.Version)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return decodeResp(resp, out)
}
