package db

import (
	"context"
	"time"

	"github.com/andras-tkcs/peek/internal/models"
)

func (s *Store) AddComment(ctx context.Context, uploadID int64, version int, selector, text, anchorKind, author, cookie, body string) (models.Comment, error) {
	now := time.Now()
	res, err := s.ExecContext(ctx, `INSERT INTO comments(upload_id,version,element_selector,element_text,anchor_kind,author_name,author_cookie,body,created_at)
		VALUES(?,?,?,?,?,?,?,?,?)`, uploadID, version, selector, text, anchorKind, author, cookie, body, now.Unix())
	if err != nil {
		return models.Comment{}, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return models.Comment{}, err
	}
	return models.Comment{
		ID: id, UploadID: uploadID, Version: version, ElementSelector: selector, ElementText: text,
		AnchorKind: anchorKind, AuthorName: author, AuthorCookie: cookie, Body: body,
		CreatedAt: time.Unix(now.Unix(), 0),
	}, nil
}

// ListComments returns comments for an upload. version 0 means all versions.
func (s *Store) ListComments(ctx context.Context, uploadID int64, version int) ([]models.Comment, error) {
	query := `SELECT id,upload_id,version,element_selector,element_text,anchor_kind,author_name,author_cookie,body,created_at
		FROM comments WHERE upload_id=?`
	args := []any{uploadID}
	if version > 0 {
		query += ` AND version=?`
		args = append(args, version)
	}
	query += ` ORDER BY created_at ASC`
	rows, err := s.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Comment
	for rows.Next() {
		var c models.Comment
		var ts int64
		if err := rows.Scan(&c.ID, &c.UploadID, &c.Version, &c.ElementSelector, &c.ElementText, &c.AnchorKind, &c.AuthorName, &c.AuthorCookie, &c.Body, &ts); err != nil {
			return nil, err
		}
		c.CreatedAt = time.Unix(ts, 0)
		out = append(out, c)
	}
	return out, rows.Err()
}
