package uploads

import (
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/puemos/peek/internal/models"
)

// VisibilityChange is a validated visibility plus the bcrypt hash to store with it
// ("" unless Visibility is password).
type VisibilityChange struct {
	Visibility   string
	PasswordHash string
}

// PrepareVisibility validates a visibility/password pair and hashes the password.
// Both inputs are trimmed. An empty visibility is invalid here; Create applies its
// own default before calling this.
func PrepareVisibility(visibility, password string) (VisibilityChange, error) {
	visibility = strings.TrimSpace(visibility)
	password = strings.TrimSpace(password)

	switch visibility {
	case models.UploadVisibilityPublic, models.UploadVisibilityPrivate, models.UploadVisibilityRestricted:
		if password != "" {
			return VisibilityChange{}, newError(KindPasswordNotAllowed, "password is only allowed with password visibility")
		}
		return VisibilityChange{Visibility: visibility}, nil
	case models.UploadVisibilityPassword:
		if password == "" {
			return VisibilityChange{}, newError(KindPasswordRequired, "password visibility requires a password")
		}
	default:
		return VisibilityChange{}, newError(KindInvalidVisibility, "visibility must be public, password, private, or restricted")
	}

	if !ValidatePasswordLength(password) {
		return VisibilityChange{}, newError(KindPasswordTooLong, "password must be 72 characters or fewer")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return VisibilityChange{}, newError(KindPasswordHash, "hash failed")
	}
	return VisibilityChange{Visibility: models.UploadVisibilityPassword, PasswordHash: string(hash)}, nil
}
