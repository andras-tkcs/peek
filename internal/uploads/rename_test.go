package uploads

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
)

type fakeRenameRepo struct {
	taken   map[string]bool
	aliases map[string]string
	renamed []string
	err     error
}

func (f *fakeRenameRepo) UploadSlugExists(_ context.Context, slug string) (bool, error) {
	return f.taken[slug], nil
}

func (f *fakeRenameRepo) ResolveSlugAlias(_ context.Context, slug string) (string, error) {
	if cur, ok := f.aliases[slug]; ok {
		return cur, nil
	}
	return "", sql.ErrNoRows
}

func (f *fakeRenameRepo) RenameUpload(_ context.Context, _ int64, newSlug, newName string) error {
	f.renamed = append(f.renamed, newSlug+"|"+newName)
	return f.err
}

func requireKind(t *testing.T, err error, kind ErrorKind) *Error {
	t.Helper()
	var uploadErr *Error
	if !errors.As(err, &uploadErr) || uploadErr.Kind != kind {
		t.Fatalf("err = %v, want kind %s", err, kind)
	}
	return uploadErr
}

func TestRenameRequiresName(t *testing.T) {
	repo := &fakeRenameRepo{}
	_, err := Rename(context.Background(), repo, "http://h", RenameInput{CurrentSlug: "old", CurrentName: "old", Name: "  "})
	requireKind(t, err, KindNameRequired)
	if len(repo.renamed) != 0 {
		t.Fatalf("renamed = %v, want none", repo.renamed)
	}
}

func TestRenameRejectsLongName(t *testing.T) {
	_, err := Rename(context.Background(), &fakeRenameRepo{}, "http://h", RenameInput{CurrentSlug: "old", CurrentName: "old", Name: strings.Repeat("a", 201)})
	requireKind(t, err, KindNameTooLong)
}

func TestRenameKeepsSlugWhenNameSlugifiesToCurrent(t *testing.T) {
	repo := &fakeRenameRepo{}
	res, err := Rename(context.Background(), repo, "http://h", RenameInput{CurrentSlug: "my-report", CurrentName: "my report", Name: "My Report"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Slug != "my-report" || res.SlugChanged {
		t.Fatalf("res = %+v", res)
	}
	if len(repo.renamed) != 1 || repo.renamed[0] != "my-report|My Report" {
		t.Fatalf("renamed = %v", repo.renamed)
	}
}

func TestRenameKeepsSlugWhenNameHasNoSlugChars(t *testing.T) {
	res, err := Rename(context.Background(), &fakeRenameRepo{}, "http://h", RenameInput{CurrentSlug: "old", CurrentName: "old", Name: "!!!"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Slug != "old" {
		t.Fatalf("slug = %q", res.Slug)
	}
}

func TestRenameKeepsSlugWhenSlugFormUnchanged(t *testing.T) {
	repo := &fakeRenameRepo{taken: map[string]bool{"index-html": true}}
	res, err := Rename(context.Background(), repo, "http://h", RenameInput{CurrentSlug: "index-html-ab12cd", CurrentName: "index.html", Name: "Index.HTML"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Slug != "index-html-ab12cd" || res.SlugChanged {
		t.Fatalf("res = %+v", res)
	}
}

func TestRenameDerivesNewSlug(t *testing.T) {
	res, err := Rename(context.Background(), &fakeRenameRepo{}, "http://h", RenameInput{CurrentSlug: "old", CurrentName: "old", Name: "New Page"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(res.Slug, "new-page-") || len(res.Slug) != len("new-page-")+6 || res.URL != "http://h/p/"+res.Slug || !res.SlugChanged {
		t.Fatalf("res = %+v", res)
	}
}

func TestRenameAddsSuffixOnClash(t *testing.T) {
	repo := &fakeRenameRepo{taken: map[string]bool{"new-page": true}}
	res, err := Rename(context.Background(), repo, "http://h", RenameInput{CurrentSlug: "old", CurrentName: "old", Name: "New Page"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(res.Slug, "new-page-") || res.Slug == "new-page" {
		t.Fatalf("slug = %q", res.Slug)
	}
}

func TestRenameReclaimsOwnAlias(t *testing.T) {
	repo := &fakeRenameRepo{taken: map[string]bool{"a": true}, aliases: map[string]string{"a": "b"}}
	res, err := Rename(context.Background(), repo, "http://h", RenameInput{CurrentSlug: "b", CurrentName: "B", Name: "A"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Slug != "a" || !res.SlugChanged {
		t.Fatalf("res = %+v", res)
	}
}

func TestRenameReportsPersistenceFailure(t *testing.T) {
	repo := &fakeRenameRepo{err: errors.New("boom")}
	_, err := Rename(context.Background(), repo, "http://h", RenameInput{CurrentSlug: "old", CurrentName: "old", Name: "New Page"})
	e := requireKind(t, err, KindPersistenceFailure)
	if e.Message != "rename failed" {
		t.Fatalf("message = %q", e.Message)
	}
}
