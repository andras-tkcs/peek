package peekd

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func getenv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func getenvInt64(k string, d int64) (int64, error) {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return d, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer", k)
	}
	return n, nil
}

func getenvInt(k string, d int) (int, error) {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return d, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer", k)
	}
	return n, nil
}

func getenvBool(k string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(k))) {
	case "":
		return false, nil
	case "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off":
		return false, nil
	default:
		return false, fmt.Errorf("%s must be a boolean", k)
	}
}

// getenvSecret returns the value of name, or the trimmed contents of the file
// named by name+"_FILE" (for Docker/Kubernetes secrets). Setting both is an error.
func getenvSecret(name string) (string, error) {
	fileVar := name + "_FILE"
	direct := os.Getenv(name)
	path := strings.TrimSpace(os.Getenv(fileVar))
	if path == "" {
		return direct, nil
	}
	if direct != "" {
		return "", fmt.Errorf("set only one of %s and %s", name, fileVar)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", fileVar, err)
	}
	v := strings.TrimSpace(string(b))
	if v == "" {
		return "", fmt.Errorf("%s points to an empty file", fileVar)
	}
	return v, nil
}

// secretFlagWarnings lists warnings for secrets passed as command-line flags.
func secretFlagWarnings(fs *flag.FlagSet) []string {
	envFor := map[string]string{
		"secret":        "PEEK_SECRET_FILE",
		"s3-secret-key": "PEEK_S3_SECRET_KEY_FILE",
		"metrics-token": "PEEK_METRICS_TOKEN_FILE",
	}
	var out []string
	fs.Visit(func(f *flag.Flag) {
		if env, ok := envFor[f.Name]; ok {
			out = append(out, fmt.Sprintf("peekd: warning: --%s is visible to other users in the process list; prefer %s", f.Name, env))
		}
	})
	return out
}
