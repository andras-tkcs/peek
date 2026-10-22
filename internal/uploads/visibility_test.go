package uploads

import (
	"errors"
	"testing"
)

func TestPrepareVisibility(t *testing.T) {
	const invalidMsg = "visibility must be public, signed-in, or restricted"
	cases := []struct {
		name       string
		visibility string
		want       string
		invalid    bool
	}{
		{name: "public", visibility: "public", want: "public"},
		{name: "signed-in", visibility: "signed-in", want: "signed-in"},
		{name: "restricted", visibility: "restricted", want: "restricted"},
		{name: "trimmed", visibility: "  public ", want: "public"},
		{name: "legacy private is signed-in", visibility: " private ", want: "signed-in"},
		{name: "empty visibility", visibility: "", invalid: true},
		{name: "unknown visibility", visibility: "secret", invalid: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := PrepareVisibility(tc.visibility)
			if !tc.invalid {
				if err != nil || got != tc.want {
					t.Fatalf("got %q, %v; want %q", got, err, tc.want)
				}
				return
			}
			var uploadErr *Error
			if !errors.As(err, &uploadErr) || uploadErr.Kind != KindInvalidVisibility || uploadErr.Message != invalidMsg {
				t.Fatalf("err = %v, want %s %q", err, KindInvalidVisibility, invalidMsg)
			}
		})
	}
}

func TestPrepareVisibilityRejectsPassword(t *testing.T) {
	_, err := PrepareVisibility("password")
	var uploadErr *Error
	if !errors.As(err, &uploadErr) || uploadErr.Kind != KindInvalidVisibility {
		t.Fatalf("err = %v, want %s", err, KindInvalidVisibility)
	}
}
