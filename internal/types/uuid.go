package types

import "github.com/google/uuid"

// NewUUIDv7 generates a new UUIDv7 string.
func NewUUIDv7() string {
	return uuid.Must(uuid.NewV7()).String()
}
