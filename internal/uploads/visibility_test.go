package uploads

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestPrepareVisibility(t *testing.T) {
	const invalidMsg = "visibility must be public, password, private, or restricted"
	cases := []struct {
		name       string
		visibility string
		password   string
		kind       ErrorKind
		msg        string
	}{
		{name: "public", visibility: "public"},
		{name: "private", visibility: "private"},
		{name: "restricted", visibility: "restricted"},
		{name: "public with password", visibility: "public", password: "x", kind: KindPasswordNotAllowed},
		{name: "restricted with password", visibility: "restricted", password: "x", kind: KindPasswordNotAllowed},
		{name: "password empty", visibility: "password", kind: KindPasswordRequired},
		{name: "password blank", visibility: "password", password: "   ", kind: KindPasswordRequired},
		{name: "empty visibility", visibility: "", kind: KindInvalidVisibility, msg: invalidMsg},
		{name: "unknown visibility", visibility: "secret", kind: KindInvalidVisibility, msg: invalidMsg},
		{name: "password too long", visibility: "password", password: strings.Repeat("a", 73), kind: KindPasswordTooLong},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := PrepareVisibility(tc.visibility, tc.password)
			if tc.kind == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got.Visibility != tc.visibility || got.PasswordHash != "" {
					t.Fatalf("got %+v, want visibility %q and empty hash", got, tc.visibility)
				}
				return
			}
			var uploadErr *Error
			if !errors.As(err, &uploadErr) || uploadErr.Kind != tc.kind {
				t.Fatalf("err = %v, want kind %s", err, tc.kind)
			}
			if tc.msg != "" && uploadErr.Message != tc.msg {
				t.Fatalf("message = %q, want %q", uploadErr.Message, tc.msg)
			}
		})
	}

	t.Run("password is trimmed and hashed", func(t *testing.T) {
		got, err := PrepareVisibility("password", "  pw  ")
		if err != nil {
			t.Fatal(err)
		}
		if got.Visibility != "password" {
			t.Fatalf("visibility = %q", got.Visibility)
		}
		if err := bcrypt.CompareHashAndPassword([]byte(got.PasswordHash), []byte("pw")); err != nil {
			t.Fatalf("hash does not match trimmed password: %v", err)
		}
	})
}
