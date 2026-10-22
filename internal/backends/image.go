package backends

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
)

const maxImageRefBytes = 255

var imageRefPattern = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]+)?(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(?:@sha256:[a-f0-9]{64})?$`)

// ValidateImageRef checks that ref is a well-formed image reference.
func ValidateImageRef(ref string) error {
	if ref == "" || len(ref) > maxImageRefBytes || !imageRefPattern.MatchString(ref) {
		return errors.New("invalid image reference")
	}
	return nil
}

// Repository returns ref without its digest and tag.
func Repository(ref string) string {
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") && i >= 0 {
		ref = ref[:i]
	}
	return ref
}

// ParseAllowedImages splits the allowed-images setting on commas and newlines.
func ParseAllowedImages(setting string) []string {
	fields := strings.FieldsFunc(setting, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' })
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// ImageAllowed reports whether ref matches an allowed prefix (entries ending
// in "/") or an allowed repository. An empty list allows nothing.
func ImageAllowed(ref string, allowed []string) bool {
	for _, p := range allowed {
		if strings.HasSuffix(p, "/") {
			if strings.HasPrefix(ref, p) {
				return true
			}
		} else if Repository(ref) == p {
			return true
		}
	}
	return false
}

// RegistryHost returns the registry that serves ref.
func RegistryHost(ref string) string {
	first, _, found := strings.Cut(ref, "/")
	if found && (strings.ContainsAny(first, ".:") || first == "localhost") {
		return first
	}
	return "docker.io"
}

// RegistryAuth encodes credentials for the X-Registry-Auth header. It returns
// an empty string when username is empty.
func RegistryAuth(username, password, server string) string {
	if username == "" {
		return ""
	}
	b, _ := json.Marshal(map[string]string{
		"username":      username,
		"password":      password,
		"serveraddress": server,
	})
	return base64.URLEncoding.EncodeToString(b)
}
