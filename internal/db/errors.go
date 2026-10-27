package db

import "errors"

var (
	ErrLastAdmin = errors.New("cannot remove or disable the last active admin")
	ErrSlugTaken = errors.New("slug is already in use")

	ErrProvisionAdmin    = errors.New("account is a Peek admin")
	ErrProvisionConflict = errors.New("account or external id is linked differently")
)
