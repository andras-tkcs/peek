package cli

import (
	"errors"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
)

func openBrowser(rawURL string) error {
	if strings.HasPrefix(rawURL, "-") {
		return errors.New("refusing to open URL starting with '-'")
	}
	if u, err := url.Parse(rawURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return errors.New("refusing to open non-http(s) URL")
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", rawURL)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", rawURL)
	default:
		cmd = exec.Command("xdg-open", rawURL)
	}
	return cmd.Start()
}
