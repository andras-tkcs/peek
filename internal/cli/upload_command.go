package cli

import (
	"fmt"
	"io"
	"mime/multipart"
	"os"
	"path/filepath"
	"strings"
)

// --- upload ---

func passwordFlagRemoved(flag string) error {
	return fmt.Errorf("%s is no longer supported: password-protected pages were removed; use --visibility restricted and 'peek grant'", flag)
}

func cmdUpload(args []string) error {
	var (
		file       string
		name       string
		visibility string
		slug       string
		nameSet    bool
	)
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--password" || a == "--password-stdin":
			return passwordFlagRemoved(a)
		case a == "--name":
			if i+1 >= len(args) {
				return fmt.Errorf("--name requires a value")
			}
			name = args[i+1]
			nameSet = true
			i++
		case a == "--visibility":
			if i+1 >= len(args) {
				return fmt.Errorf("--visibility requires a value")
			}
			visibility = args[i+1]
			i++
		case a == "--slug":
			if i+1 >= len(args) {
				return fmt.Errorf("--slug requires a value")
			}
			slug = strings.TrimSpace(args[i+1])
			i++
		case strings.HasPrefix(a, "-"):
			return fmt.Errorf("unknown flag: %s", a)
		default:
			if file != "" {
				return fmt.Errorf("only one file at a time")
			}
			file = a
		}
	}
	if file == "" {
		return fmt.Errorf("usage: peek upload <file.html> [--visibility public|signed-in|restricted] [--name <name>] [--slug <slug>]")
	}
	if slug != "" {
		if _, err := slugPath(slug); err != nil {
			return err
		}
		if visibility != "" {
			return fmt.Errorf("--slug adds a new version to an existing page; change visibility with 'peek visibility'")
		}
		if nameSet {
			return fmt.Errorf("--name cannot be used with --slug; the page keeps its name")
		}
	} else if visibility == "" {
		visibility = "restricted"
	}
	if slug == "" && !validVisibility(visibility) {
		return fmt.Errorf("visibility must be public, signed-in, or restricted")
	}

	cfg, err := LoadConfig()
	if err != nil {
		return err
	}
	c, err := newClient(cfg)
	if err != nil {
		return err
	}

	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()

	if name == "" {
		name = fileNameWithoutExt(file)
	}
	body, contentType := streamMultipartUpload(f, name, visibility, slug)
	resp, err := c.req("POST", "/api/upload", body, contentType)
	if err != nil {
		_ = body.Close()
		return err
	}
	defer resp.Body.Close()
	var out struct {
		Slug       string `json:"slug"`
		URL        string `json:"url"`
		Visibility string `json:"visibility"`
		Version    int    `json:"version"`
		VersionURL string `json:"version_url"`
	}
	if err := decodeResp(resp, &out); err != nil {
		return err
	}
	fmt.Printf("uploaded: %s\n", out.URL)
	fmt.Printf("slug:     %s\n", out.Slug)
	fmt.Printf("version:  %d\n", out.Version)
	if slug != "" {
		fmt.Printf("version url: %s\n", out.VersionURL)
	}
	fmt.Printf("visibility: %s\n", out.Visibility)
	return nil
}

func streamMultipartUpload(file io.Reader, filename, visibility, slug string) (io.ReadCloser, string) {
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	go func() {
		if err := writeMultipartUpload(mw, file, filename, visibility, slug); err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		_ = pw.Close()
	}()
	return pr, mw.FormDataContentType()
}

func writeMultipartUpload(mw *multipart.Writer, file io.Reader, filename, visibility, slug string) error {
	fw, err := mw.CreateFormFile("file", filename)
	if err != nil {
		return err
	}
	if _, err := io.Copy(fw, file); err != nil {
		return err
	}
	if visibility != "" {
		if err := mw.WriteField("visibility", visibility); err != nil {
			return err
		}
	}
	if slug != "" {
		if err := mw.WriteField("slug", slug); err != nil {
			return err
		}
	}
	return mw.Close()
}

func validVisibility(visibility string) bool {
	return visibility == "public" || visibility == "signed-in" || visibility == "private" || visibility == "restricted"
}

func fileNameWithoutExt(path string) string {
	base := filepath.Base(path)
	ext := filepath.Ext(base)
	if ext != "" {
		base = base[:len(base)-len(ext)]
	}
	if base == "" {
		base = "page"
	}
	return base
}
