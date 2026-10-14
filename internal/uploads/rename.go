package uploads

import (
	"context"
	"log/slog"
	"strings"
	"unicode/utf8"
)

const (
	KindNameRequired ErrorKind = "name_required"
	KindNameTooLong  ErrorKind = "name_too_long"
)

const (
	maxNameLength      = 200
	nameTooLongMessage = "name must be 200 characters or fewer"
)

// RenameRepository is the persistence a rename needs.
type RenameRepository interface {
	UploadSlugExists(ctx context.Context, slug string) (bool, error)
	ResolveSlugAlias(ctx context.Context, slug string) (string, error)
	RenameUpload(ctx context.Context, uploadID int64, newSlug, newName string) error
}

type RenameInput struct {
	UploadID    int64
	CurrentSlug string
	CurrentName string
	Name        string
}

type RenameResult struct {
	Slug        string
	URL         string // baseURL + "/p/" + Slug
	Name        string
	SlugChanged bool
}

// Rename changes an upload's display name and derives its link from the new name
// the same way upload does (name slug plus a random suffix). The link is kept when
// the new name's slug form is empty, equals the current slug, or equals the old
// name's slug form; a page's own unsuffixed old link is taken back instead of
// minting a new one.
func Rename(ctx context.Context, repo RenameRepository, baseURL string, in RenameInput) (*RenameResult, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return nil, newError(KindNameRequired, "name is required")
	}
	if utf8.RuneCountInString(name) > maxNameLength {
		return nil, newError(KindNameTooLong, nameTooLongMessage)
	}

	slug := in.CurrentSlug
	base := slugify(name)
	switch {
	case base == "", base == in.CurrentSlug, base == slugify(in.CurrentName):
	default:
		if cur, err := repo.ResolveSlugAlias(ctx, base); err == nil && cur == in.CurrentSlug {
			slug = base
		} else {
			var gerr error
			slug, gerr = generateSlugFromName(ctx, name, repo)
			if gerr != nil {
				return nil, newError(KindSlugGeneration, "slug generation failed")
			}
		}
	}

	if err := repo.RenameUpload(ctx, in.UploadID, slug, name); err != nil {
		slog.Error("rename upload failed", "upload_id", in.UploadID, "err", err)
		return nil, newError(KindPersistenceFailure, "rename failed")
	}
	return &RenameResult{Slug: slug, URL: baseURL + "/p/" + slug, Name: name, SlugChanged: slug != in.CurrentSlug}, nil
}
