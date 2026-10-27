package uploads

import (
	"bytes"
	"context"
	"errors"
	"io"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/privacyfence/peek/internal/db"
	"github.com/privacyfence/peek/internal/models"
	"github.com/privacyfence/peek/internal/uploadquota"
)

type memoryStorage struct {
	saved     map[string][]byte
	deleted   []string
	deleteErr error
	saveErr   error
}

func newMemoryStorage() *memoryStorage {
	return &memoryStorage{saved: map[string][]byte{}}
}

func (m *memoryStorage) Save(_ context.Context, slug string, data []byte) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	m.saved[slug] = append([]byte(nil), data...)
	return nil
}

func (m *memoryStorage) Open(_ context.Context, slug string) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(m.saved[slug])), nil
}

func (m *memoryStorage) Delete(_ context.Context, slug string) error {
	m.deleted = append(m.deleted, slug)
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.saved, slug)
	return nil
}

func TestCreateDefaultsToRestricted(t *testing.T) {
	store, owner := serviceTestStore(t)
	defer store.Close()
	svc := Service{Repository: store, Storage: newMemoryStorage(), BaseURL: "http://localhost:7700"}

	up, err := svc.Create(context.Background(), CreateInput{
		OwnerAccountID: owner.AccountID,
		OwnerTokenID:   owner.ID,
		Name:           "page.html",
		Data:           []byte("<!doctype html><html></html>"),
	})
	if err != nil {
		t.Fatalf("create with default visibility: %v", err)
	}
	if up.Visibility != models.UploadVisibilityRestricted {
		t.Fatalf("result visibility = %q, want restricted", up.Visibility)
	}
	got, err := store.GetUpload(context.Background(), up.Slug)
	if err != nil || got.Visibility != models.UploadVisibilityRestricted {
		t.Fatalf("stored upload = %+v, err = %v", got, err)
	}
}

func TestServiceDeletesStorageObjectWhenDBRejectsUpload(t *testing.T) {
	store, owner := serviceTestStore(t)
	defer store.Close()
	st := newMemoryStorage()
	svc := Service{Repository: store, Storage: st, BaseURL: "http://localhost:7700"}

	_, err := svc.Create(context.Background(), CreateInput{
		OwnerAccountID: owner.AccountID,
		OwnerTokenID:   owner.ID,
		Name:           "page.html",
		Visibility:     "public",
		Data:           []byte("<!doctype html><html></html>"),
		Limits:         uploadquota.Limits{MaxTotalSize: 1},
	})
	if err == nil {
		t.Fatal("expected quota error")
	}
	var uploadErr *Error
	if !errors.As(err, &uploadErr) {
		t.Fatalf("error = %T %[1]v, want *uploads.Error", err)
	}
	if uploadErr.Kind != KindTotalQuotaExceeded {
		t.Fatalf("kind = %q, want %q", uploadErr.Kind, KindTotalQuotaExceeded)
	}
	if len(st.deleted) != 1 {
		t.Fatalf("expected one cleanup delete, got %+v", st.deleted)
	}
	if len(st.saved) != 0 {
		t.Fatalf("quota failure left saved object: %+v", st.saved)
	}
}

func TestServiceReturnsCleanupErrorWhenStorageDeleteFails(t *testing.T) {
	store, owner := serviceTestStore(t)
	defer store.Close()
	deleteErr := errors.New("delete failed")
	st := newMemoryStorage()
	st.deleteErr = deleteErr
	svc := Service{Repository: store, Storage: st, BaseURL: "http://localhost:7700"}

	_, err := svc.Create(context.Background(), CreateInput{
		OwnerAccountID: owner.AccountID,
		OwnerTokenID:   owner.ID,
		Name:           "page.html",
		Visibility:     "public",
		Data:           []byte("<!doctype html><html></html>"),
		Limits:         uploadquota.Limits{MaxTotalSize: 1},
	})
	if err == nil {
		t.Fatal("expected quota error")
	}
	var uploadErr *Error
	if !errors.As(err, &uploadErr) {
		t.Fatalf("error = %T %[1]v, want *uploads.Error", err)
	}
	if uploadErr.Kind != KindTotalQuotaExceeded {
		t.Fatalf("kind = %q, want %q", uploadErr.Kind, KindTotalQuotaExceeded)
	}
	var cleanupErr *CleanupError
	if !errors.As(err, &cleanupErr) {
		t.Fatalf("error = %T %[1]v, want *uploads.CleanupError", err)
	}
	if !errors.Is(err, deleteErr) {
		t.Fatalf("error does not wrap delete failure: %v", err)
	}
	if len(st.deleted) != 1 || st.deleted[0] != cleanupErr.Slug {
		t.Fatalf("cleanup deletes = %+v, cleanup slug = %q", st.deleted, cleanupErr.Slug)
	}
	if _, ok := st.saved[cleanupErr.Slug]; !ok {
		t.Fatalf("storage object should remain when cleanup delete fails: saved=%+v cleanup=%+v", st.saved, cleanupErr)
	}
}

func serviceTestStore(t *testing.T) (*db.Store, *models.Token) {
	t.Helper()
	store, err := db.Open(filepath.Join(t.TempDir(), "peek.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateToken(context.Background(), "owner", "owner", false, 0); err != nil {
		t.Fatal(err)
	}
	owner, err := store.GetToken(context.Background(), "owner")
	if err != nil {
		t.Fatal(err)
	}
	return store, owner
}

type failingVersionRepo struct {
	Repository
	err error
}

func (f failingVersionRepo) CreateVersionChecked(context.Context, int64, string, int64, int64, uploadquota.Limits) (int, error) {
	return 0, f.err
}

func TestAddVersionStoresUnderVersionKey(t *testing.T) {
	store, owner := serviceTestStore(t)
	defer store.Close()
	st := newMemoryStorage()
	svc := Service{Repository: store, Storage: st, BaseURL: "http://localhost:7700"}
	created, err := svc.Create(context.Background(), CreateInput{
		OwnerAccountID: owner.AccountID,
		OwnerTokenID:   owner.ID,
		Name:           "page",
		Visibility:     "public",
		Data:           []byte("<!doctype html><html></html>"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.Version != 1 {
		t.Fatalf("create version = %d, want 1", created.Version)
	}
	u, err := store.GetUpload(context.Background(), created.Slug)
	if err != nil {
		t.Fatal(err)
	}

	res, err := svc.AddVersion(context.Background(), AddVersionInput{
		UploadID:       u.ID,
		Slug:           created.Slug,
		ActorAccountID: owner.AccountID,
		Data:           []byte("<!doctype html><html>v2</html>"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Version != 2 {
		t.Fatalf("version = %d, want 2", res.Version)
	}
	if want := "http://localhost:7700/p/" + created.Slug + "/v/2"; res.VersionURL != want {
		t.Fatalf("version url = %q, want %q", res.VersionURL, want)
	}
	pattern := regexp.MustCompile(`^versions/` + regexp.QuoteMeta(created.Slug) + `/[0-9a-f]{16}$`)
	found := 0
	for key := range st.saved {
		if pattern.MatchString(key) {
			found++
		}
	}
	if found != 1 {
		t.Fatalf("saved keys = %+v, want one matching %s", st.saved, pattern)
	}
}

func TestAddVersionCleansUpObjectOnRepositoryError(t *testing.T) {
	store, _ := serviceTestStore(t)
	defer store.Close()
	st := newMemoryStorage()
	svc := Service{
		Repository: failingVersionRepo{Repository: store, err: uploadquota.ErrTotalExceeded},
		Storage:    st,
		BaseURL:    "http://localhost:7700",
	}
	_, err := svc.AddVersion(context.Background(), AddVersionInput{
		UploadID: 1,
		Slug:     "page",
		Data:     []byte("<!doctype html><html></html>"),
	})
	var uploadErr *Error
	if !errors.As(err, &uploadErr) || uploadErr.Kind != KindTotalQuotaExceeded {
		t.Fatalf("error = %v, want total quota error", err)
	}
	if len(st.deleted) != 1 || len(st.saved) != 0 {
		t.Fatalf("deleted=%+v saved=%+v, want object cleaned up", st.deleted, st.saved)
	}
}

func TestCreateAcceptsRestricted(t *testing.T) {
	store, owner := serviceTestStore(t)
	defer store.Close()
	svc := Service{Repository: store, Storage: newMemoryStorage(), BaseURL: "http://localhost:7700"}
	up, err := svc.Create(context.Background(), CreateInput{
		OwnerAccountID: owner.AccountID,
		OwnerTokenID:   owner.ID,
		Name:           "page.html",
		Visibility:     "restricted",
		Data:           []byte("<!doctype html><html></html>"),
	})
	if err != nil {
		t.Fatalf("create restricted upload: %v", err)
	}
	if up.Visibility != "restricted" {
		t.Fatalf("result visibility = %q", up.Visibility)
	}
	got, err := store.GetUpload(context.Background(), up.Slug)
	if err != nil || got.Visibility != "restricted" {
		t.Fatalf("stored upload = %+v, err = %v", got, err)
	}
}

func TestCreateRejectsNameOver200Characters(t *testing.T) {
	store, owner := serviceTestStore(t)
	defer store.Close()
	st := newMemoryStorage()
	svc := Service{Repository: store, Storage: st, BaseURL: "http://localhost:7700"}

	_, err := svc.Create(context.Background(), CreateInput{
		OwnerAccountID: owner.AccountID,
		OwnerTokenID:   owner.ID,
		Name:           strings.Repeat("a", 201),
		Data:           []byte("<!doctype html><html></html>"),
	})
	var uploadErr *Error
	if !errors.As(err, &uploadErr) {
		t.Fatalf("error = %T %[1]v, want *uploads.Error", err)
	}
	if uploadErr.Kind != KindNameTooLong || uploadErr.Message != "name must be 200 characters or fewer" {
		t.Fatalf("error = %+v", uploadErr)
	}
	if len(st.saved) != 0 {
		t.Fatalf("rejected name wrote storage object: %+v", st.saved)
	}
}

func TestCreateAcceptsNameOf200Characters(t *testing.T) {
	store, owner := serviceTestStore(t)
	defer store.Close()
	svc := Service{Repository: store, Storage: newMemoryStorage(), BaseURL: "http://localhost:7700"}

	_, err := svc.Create(context.Background(), CreateInput{
		OwnerAccountID: owner.AccountID,
		OwnerTokenID:   owner.ID,
		Name:           strings.Repeat("é", 200),
		Visibility:     models.UploadVisibilityPublic,
		Data:           []byte("<!doctype html><html></html>"),
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
}

type slugErrRepo struct {
	Repository
}

func (slugErrRepo) UploadSlugExists(context.Context, string) (bool, error) {
	return false, errors.New("lookup failed")
}

func TestErrorStrings(t *testing.T) {
	if got := (&Error{Kind: KindEmptyFile, Message: "empty file"}).Error(); got != "empty file" {
		t.Fatalf("Error() = %q", got)
	}
	inner := errors.New("disk")
	ce := &CleanupError{Slug: "abc", Err: inner}
	if got := ce.Error(); got != "cleanup storage object abc: disk" {
		t.Fatalf("CleanupError() = %q", got)
	}
	if !errors.Is(ce, inner) {
		t.Fatal("CleanupError should unwrap")
	}
}

func TestCreateRejectsBadInputAndReportsFailures(t *testing.T) {
	store, owner := serviceTestStore(t)
	defer store.Close()
	ctx := context.Background()
	html := []byte("<!doctype html><html></html>")
	base := CreateInput{OwnerAccountID: owner.AccountID, OwnerTokenID: owner.ID, Name: "x", Visibility: "public", Data: html}

	cases := []struct {
		name string
		svc  Service
		mod  func(*CreateInput)
		kind ErrorKind
	}{
		{"empty data", Service{Repository: store, Storage: newMemoryStorage()}, func(in *CreateInput) { in.Data = nil }, KindEmptyFile},
		{"not html", Service{Repository: store, Storage: newMemoryStorage()}, func(in *CreateInput) { in.Data = []byte("plain text") }, KindInvalidHTML},
		{"slug failure", Service{Repository: slugErrRepo{store}, Storage: newMemoryStorage()}, func(*CreateInput) {}, KindSlugGeneration},
		{"save failure", Service{Repository: store, Storage: &memoryStorage{saved: map[string][]byte{}, saveErr: errors.New("full")}}, func(*CreateInput) {}, KindStorageWrite},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := base
			tc.mod(&in)
			_, err := tc.svc.Create(ctx, in)
			var ue *Error
			if !errors.As(err, &ue) || ue.Kind != tc.kind {
				t.Fatalf("err = %v, want kind %s", err, tc.kind)
			}
		})
	}

	t.Run("empty name defaults to page", func(t *testing.T) {
		in := base
		in.Name = "  "
		res, err := Service{Repository: store, Storage: newMemoryStorage()}.Create(ctx, in)
		if err != nil || res.Name != "page" {
			t.Fatalf("res=%+v err=%v", res, err)
		}
	})
}

func TestAddVersionRejectsAndReportsFailures(t *testing.T) {
	store, _ := serviceTestStore(t)
	defer store.Close()
	ctx := context.Background()
	html := []byte("<!doctype html><html></html>")

	for name, tc := range map[string]struct {
		svc  Service
		data []byte
		kind ErrorKind
	}{
		"empty":        {Service{Repository: store, Storage: newMemoryStorage()}, nil, KindEmptyFile},
		"not html":     {Service{Repository: store, Storage: newMemoryStorage()}, []byte("plain"), KindInvalidHTML},
		"save failure": {Service{Repository: store, Storage: &memoryStorage{saved: map[string][]byte{}, saveErr: errors.New("full")}}, html, KindStorageWrite},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := tc.svc.AddVersion(ctx, AddVersionInput{UploadID: 1, Slug: "page", Data: tc.data})
			var ue *Error
			if !errors.As(err, &ue) || ue.Kind != tc.kind {
				t.Fatalf("err = %v, want kind %s", err, tc.kind)
			}
		})
	}

	t.Run("cleanup failure is joined", func(t *testing.T) {
		st := newMemoryStorage()
		st.deleteErr = errors.New("rm failed")
		svc := Service{Repository: failingVersionRepo{Repository: store, err: errors.New("db down")}, Storage: st}
		_, err := svc.AddVersion(ctx, AddVersionInput{UploadID: 1, Slug: "page", Data: html})
		var ce *CleanupError
		var ue *Error
		if !errors.As(err, &ce) || !errors.As(err, &ue) || ue.Kind != KindPersistenceFailure {
			t.Fatalf("err = %v, want persistence failure joined with cleanup error", err)
		}
	})
}

func TestStoreErrorKinds(t *testing.T) {
	for _, tc := range []struct {
		err  error
		kind ErrorKind
	}{
		{uploadquota.ErrTotalExceeded, KindTotalQuotaExceeded},
		{uploadquota.ErrOwnerCountExceeded, KindOwnerCountExceeded},
		{uploadquota.ErrOwnerStorageExceeded, KindOwnerStorageExceeded},
		{errors.New("other"), KindPersistenceFailure},
	} {
		var ue *Error
		if !errors.As(storeError(tc.err), &ue) || ue.Kind != tc.kind {
			t.Fatalf("storeError(%v) kind = %v, want %s", tc.err, ue, tc.kind)
		}
	}
}
