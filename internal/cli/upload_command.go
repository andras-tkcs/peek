package cli

import (
	"bufio"
	"fmt"
	"io"
	"mime/multipart"
	"os"
	"path/filepath"
	"strings"
)

// --- upload ---

func cmdUpload(args []string) error {
	var (
		file          string
		password      string
		passwordStdin bool
		name          string
		visibility    string
		slug          string
		nameSet       bool

		usedPasswordFlag bool
	)
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--password":
			if i+1 >= len(args) {
				return fmt.Errorf("--password requires a value")
			}
			password = args[i+1]
			usedPasswordFlag = true
			i++
		case a == "--password-stdin":
			passwordStdin = true
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
		return fmt.Errorf("usage: peek upload <file.html> [--visibility public|password|private|restricted] [--password <pw>] [--name <name>] [--slug <slug>]")
	}
	if slug != "" {
		if _, err := slugPath(slug); err != nil {
			return err
		}
		if visibility != "" || password != "" || passwordStdin {
			return fmt.Errorf("--slug adds a new version to an existing page; change visibility with 'peek visibility'")
		}
		if nameSet {
			return fmt.Errorf("--name cannot be used with --slug; the page keeps its name")
		}
	} else if visibility == "" {
		visibility = "password"
	}
	if slug == "" && !validVisibility(visibility) {
		return fmt.Errorf("visibility must be public, password, private, or restricted")
	}
	if password != "" && passwordStdin {
		return fmt.Errorf("use only one of --password or --password-stdin")
	}
	if passwordStdin {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && err != io.EOF {
			return err
		}
		password = strings.TrimSpace(line)
		if password == "" {
			return fmt.Errorf("no password provided on stdin")
		}
	}
	if slug == "" && visibility == "password" && password == "" {
		return fmt.Errorf("password visibility requires --password or --password-stdin")
	}
	if slug == "" && visibility != "password" && password != "" {
		return fmt.Errorf("--password is only valid with --visibility password")
	}
	if usedPasswordFlag {
		fmt.Fprintln(os.Stderr, "warning: --password is exposed in your shell history and process list (ps). Prefer --password-stdin.")
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
	body, contentType := streamMultipartUpload(f, name, visibility, password, slug)
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

func streamMultipartUpload(file io.Reader, filename, visibility, password, slug string) (io.ReadCloser, string) {
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	go func() {
		if err := writeMultipartUpload(mw, file, filename, visibility, password, slug); err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		_ = pw.Close()
	}()
	return pr, mw.FormDataContentType()
}

func writeMultipartUpload(mw *multipart.Writer, file io.Reader, filename, visibility, password, slug string) error {
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
	if password != "" {
		if err := mw.WriteField("password", password); err != nil {
			return err
		}
	}
	return mw.Close()
}

func validVisibility(visibility string) bool {
	return visibility == "public" || visibility == "password" || visibility == "private" || visibility == "restricted"
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
