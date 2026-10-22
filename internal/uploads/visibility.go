package uploads

import (
	"strings"

	"github.com/andras-tkcs/peek/internal/models"
)

// PrepareVisibility validates and normalizes a visibility. The legacy "private"
// maps to signed-in. An empty visibility is invalid here; Create applies its own
// default before calling this.
func PrepareVisibility(visibility string) (string, error) {
	visibility = strings.TrimSpace(visibility)
	if visibility == models.LegacyVisibilityPrivate {
		visibility = models.UploadVisibilitySignedIn
	}
	switch visibility {
	case models.UploadVisibilityPublic, models.UploadVisibilitySignedIn, models.UploadVisibilityRestricted:
		return visibility, nil
	}
	return "", newError(KindInvalidVisibility, "visibility must be public, signed-in, or restricted")
}
