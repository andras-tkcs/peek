package server

import (
	"context"
	"errors"
	"testing"
)

func TestSetCovDeleteUploadFallsBackToSlugKeyWithoutVersions(t *testing.T) {
	s, _ := newHandlerTestServer(t)
	ctx := context.Background()
	u := newTwoVersionPage(t, s, "setcov-del", "public", "")
	versions, err := s.store.ListUploadVersions(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range versions {
		if err := s.store.DeleteUploadVersion(ctx, u.ID, v.Version); err != nil {
			t.Fatalf("delete version %d: %v", v.Version, err)
		}
	}
	if left, _ := s.store.ListUploadVersions(ctx, u.ID); len(left) != 0 {
		t.Fatalf("store keeps %d versions after delete", len(left))
	}
	if err := s.deleteUpload(ctx, *u); err != nil {
		t.Fatalf("deleteUpload: %v", err)
	}
	if _, err := s.store.GetUpload(ctx, "setcov-del"); err == nil {
		t.Fatal("upload record still present")
	}
}

func TestSetCovDeleteUploadVersionListFailure(t *testing.T) {
	s, store, _, adminID := newFaultServer(t)
	u := newTwoVersionPage(t, s, "setcov-listfail", "public", "")
	_ = adminID
	dropTable(t, store, "upload_versions")
	if err := s.deleteUpload(context.Background(), *u); err == nil {
		t.Fatal("expected list versions error")
	}
}

func TestSetCovDeleteUploadStorageFailure(t *testing.T) {
	s, store, storage, _ := newFaultServer(t)
	u := newTwoVersionPage(t, s, "setcov-storefail", "public", "")
	storage.deleteErr = errors.New("storage down")
	err := s.deleteUpload(context.Background(), *u)
	if err == nil {
		t.Fatal("expected storage delete error")
	}
	if _, gerr := store.GetUpload(context.Background(), "setcov-storefail"); gerr != nil {
		t.Fatalf("upload record removed despite storage failure: %v", gerr)
	}
}
