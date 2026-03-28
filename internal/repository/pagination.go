package repository

import "time"

// PaginationParams holds cursor-based pagination parameters for list queries.
type PaginationParams struct {
	Cursor *time.Time
	Limit  int // Fetch Limit+1 rows; the caller uses the extra row to determine has_more.
}
