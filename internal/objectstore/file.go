package objectstore

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type FileStorage struct {
	Dir string
}

func (fs *FileStorage) objectPath(slug string) (string, error) {
	name, err := objectName(slug)
	if err != nil {
		return "", err
	}
	path := filepath.Join(fs.Dir, name)
	if !strings.HasPrefix(path, filepath.Clean(fs.Dir)+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: %q", ErrInvalidSlug, slug)
	}
	return path, nil
}

func (fs *FileStorage) Save(_ context.Context, slug string, data []byte) error {
	path, err := fs.objectPath(slug)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func (fs *FileStorage) Open(_ context.Context, slug string) (io.ReadCloser, error) {
	path, err := fs.objectPath(slug)
	if err != nil {
		return nil, err
	}
	return os.Open(path)
}

func (fs *FileStorage) Delete(_ context.Context, slug string) error {
	path, err := fs.objectPath(slug)
	if err != nil {
		return err
	}
	err = os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
