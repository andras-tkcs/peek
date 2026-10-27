package internal_test

import (
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type listedPackage struct {
	ImportPath string
	Imports    []string
}

func TestInternalPackageDependencyDirection(t *testing.T) {
	root := moduleRoot(t)
	cmd := exec.Command("go", "list", "-json", "./internal/...")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list internal packages: %v", err)
	}

	dec := json.NewDecoder(strings.NewReader(string(out)))
	var packages []listedPackage
	for {
		var pkg listedPackage
		if err := dec.Decode(&pkg); err == io.EOF {
			break
		} else if err != nil {
			t.Fatalf("decode go list output: %v", err)
		}
		packages = append(packages, pkg)
	}

	rules := []struct {
		pkg             string
		forbiddenImport []string
	}{
		{
			pkg: "github.com/privacyfence/peek/internal/backends",
			forbiddenImport: []string{
				"github.com/privacyfence/peek/internal/cli",
				"github.com/privacyfence/peek/internal/db",
				"github.com/privacyfence/peek/internal/groups",
				"github.com/privacyfence/peek/internal/mail",
				"github.com/privacyfence/peek/internal/models",
				"github.com/privacyfence/peek/internal/objectstore",
				"github.com/privacyfence/peek/internal/peekd",
				"github.com/privacyfence/peek/internal/server",
				"github.com/privacyfence/peek/internal/uploads",
				"github.com/privacyfence/peek/internal/uploadquota",
				"github.com/privacyfence/peek/internal/version",
				"github.com/privacyfence/peek/internal/web",
			},
		},
		{
			pkg: "github.com/privacyfence/peek/internal/cli",
			forbiddenImport: []string{
				"github.com/privacyfence/peek/internal/db",
				"github.com/privacyfence/peek/internal/objectstore",
				"github.com/privacyfence/peek/internal/server",
				"github.com/privacyfence/peek/internal/uploads",
				"github.com/privacyfence/peek/internal/web",
			},
		},
		{
			pkg: "github.com/privacyfence/peek/internal/db",
			forbiddenImport: []string{
				"net/http",
				"github.com/privacyfence/peek/internal/cli",
				"github.com/privacyfence/peek/internal/objectstore",
				"github.com/privacyfence/peek/internal/server",
				"github.com/privacyfence/peek/internal/uploads",
				"github.com/privacyfence/peek/internal/web",
			},
		},
		{
			pkg: "github.com/privacyfence/peek/internal/groups",
			forbiddenImport: []string{
				"github.com/privacyfence/peek/internal/cli",
				"github.com/privacyfence/peek/internal/db",
				"github.com/privacyfence/peek/internal/objectstore",
				"github.com/privacyfence/peek/internal/server",
				"github.com/privacyfence/peek/internal/uploads",
				"github.com/privacyfence/peek/internal/web",
			},
		},
		{
			pkg: "github.com/privacyfence/peek/internal/server",
			forbiddenImport: []string{
				"github.com/privacyfence/peek/internal/groups",
			},
		},
		{
			pkg: "github.com/privacyfence/peek/internal/mail",
			forbiddenImport: []string{
				"net/http",
				"github.com/privacyfence/peek/internal/cli",
				"github.com/privacyfence/peek/internal/db",
				"github.com/privacyfence/peek/internal/groups",
				"github.com/privacyfence/peek/internal/models",
				"github.com/privacyfence/peek/internal/objectstore",
				"github.com/privacyfence/peek/internal/peekd",
				"github.com/privacyfence/peek/internal/server",
				"github.com/privacyfence/peek/internal/uploads",
				"github.com/privacyfence/peek/internal/uploadquota",
				"github.com/privacyfence/peek/internal/version",
				"github.com/privacyfence/peek/internal/web",
			},
		},
		{
			pkg: "github.com/privacyfence/peek/internal/objectstore",
			forbiddenImport: []string{
				"github.com/privacyfence/peek/internal/db",
				"github.com/privacyfence/peek/internal/server",
				"github.com/privacyfence/peek/internal/uploads",
				"github.com/privacyfence/peek/internal/web",
			},
		},
		{
			pkg: "github.com/privacyfence/peek/internal/uploads",
			forbiddenImport: []string{
				"net/http",
				"github.com/privacyfence/peek/internal/db",
				"github.com/privacyfence/peek/internal/server",
				"github.com/privacyfence/peek/internal/web",
			},
		},
		{
			pkg: "github.com/privacyfence/peek/internal/web",
			forbiddenImport: []string{
				"github.com/privacyfence/peek/internal/cli",
				"github.com/privacyfence/peek/internal/db",
				"github.com/privacyfence/peek/internal/objectstore",
				"github.com/privacyfence/peek/internal/server",
				"github.com/privacyfence/peek/internal/uploads",
			},
		},
	}

	for _, rule := range rules {
		t.Run(strings.TrimPrefix(rule.pkg, "github.com/privacyfence/peek/internal/"), func(t *testing.T) {
			pkg, ok := findPackage(packages, rule.pkg)
			if !ok {
				t.Fatalf("package %s not found", rule.pkg)
			}
			for _, forbidden := range rule.forbiddenImport {
				if slices.Contains(pkg.Imports, forbidden) {
					t.Fatalf("%s imports forbidden package %s", rule.pkg, forbidden)
				}
			}
		})
	}
}

func findPackage(packages []listedPackage, importPath string) (listedPackage, bool) {
	for _, pkg := range packages {
		if pkg.ImportPath == importPath {
			return pkg, true
		}
	}
	return listedPackage{}, false
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}
