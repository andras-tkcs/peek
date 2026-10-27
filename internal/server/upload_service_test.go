package server

import (
	"bytes"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/privacyfence/peek/internal/uploads"
)

func TestUploadHTTPErrorMapsDomainKinds(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantStatus int
		wantMsg    string
	}{
		{
			name:       "invalid html",
			err:        &uploads.Error{Kind: uploads.KindInvalidHTML, Message: "file does not look like HTML"},
			wantStatus: http.StatusUnsupportedMediaType,
			wantMsg:    "file does not look like HTML",
		},
		{
			name:       "quota",
			err:        &uploads.Error{Kind: uploads.KindTotalQuotaExceeded, Message: "total storage quota exceeded"},
			wantStatus: http.StatusRequestEntityTooLarge,
			wantMsg:    "total storage quota exceeded",
		},
		{
			name: "joined cleanup error",
			err: errors.Join(
				&uploads.Error{Kind: uploads.KindTotalQuotaExceeded, Message: "total storage quota exceeded"},
				&uploads.CleanupError{Slug: "page", Err: errors.New("delete failed")},
			),
			wantStatus: http.StatusRequestEntityTooLarge,
			wantMsg:    "total storage quota exceeded",
		},
		{
			name:       "plain error",
			err:        errors.New("boom"),
			wantStatus: http.StatusInternalServerError,
			wantMsg:    "upload failed",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, msg := uploadHTTPError(tc.err)
			if status != tc.wantStatus || msg != tc.wantMsg {
				t.Fatalf("uploadHTTPError() = (%d, %q), want (%d, %q)", status, msg, tc.wantStatus, tc.wantMsg)
			}
		})
	}
}

func TestLogUploadErrorReportsCleanupFailureOnly(t *testing.T) {
	var logs bytes.Buffer
	oldLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(oldLogger) })

	logUploadError(&uploads.Error{Kind: uploads.KindInvalidHTML, Message: "file does not look like HTML"})
	if logs.Len() != 0 {
		t.Fatalf("ordinary upload error was logged: %s", logs.String())
	}

	logUploadError(errors.Join(
		&uploads.Error{Kind: uploads.KindTotalQuotaExceeded, Message: "total storage quota exceeded"},
		&uploads.CleanupError{Slug: "page", Err: errors.New("delete failed")},
	))
	if !strings.Contains(logs.String(), "upload storage cleanup failed") {
		t.Fatalf("cleanup failure was not logged: %s", logs.String())
	}
	if !strings.Contains(logs.String(), "slug=page") {
		t.Fatalf("cleanup slug was not logged: %s", logs.String())
	}
}

func TestAPIUploadRejectsLongName(t *testing.T) {
	s, tok := newHandlerTestServer(t)
	rec := doRequest(t, s, http.MethodPost, "/api/upload?visibility=public&filename="+strings.Repeat("a", 201), strings.NewReader("<!doctype html><html></html>"), asBearer(tok), func(r *http.Request) { r.Header.Set("Content-Type", "text/html") })
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "name must be 200 characters or fewer") {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
}

func TestSetCovUploadHTTPErrorFallbacks(t *testing.T) {
	if status, msg := uploadHTTPError(errors.New("boom")); status != http.StatusInternalServerError || msg != "upload failed" {
		t.Fatalf("non-upload error = %d %q", status, msg)
	}
	err := &uploads.Error{Kind: uploads.ErrorKind("something_new"), Message: "unmapped"}
	if status, msg := uploadHTTPError(err); status != http.StatusInternalServerError || msg != "unmapped" {
		t.Fatalf("unknown kind = %d %q", status, msg)
	}
}
