package api

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

const (
	defaultPageLimit = 50
	maxPageLimit     = 200
)

// paginationParams holds cursor-based pagination parameters parsed from query strings.
type paginationParams struct {
	Cursor *time.Time
	Limit  int
}

// paginationMeta is included in the API response meta for paginated endpoints.
type paginationMeta struct {
	NextCursor string `json:"next_cursor,omitempty"`
	HasMore    bool   `json:"has_more"`
}

// parsePagination extracts cursor and limit from the request query parameters.
// cursor is a base64-encoded RFC3339Nano timestamp; limit defaults to 50 (max 200).
func parsePagination(r *http.Request) (paginationParams, error) {
	p := paginationParams{
		Limit: defaultPageLimit,
	}

	if raw := r.URL.Query().Get("cursor"); raw != "" {
		decoded, err := base64.URLEncoding.DecodeString(raw)
		if err != nil {
			return p, fmt.Errorf("invalid cursor encoding")
		}
		t, err := time.Parse(time.RFC3339Nano, string(decoded))
		if err != nil {
			return p, fmt.Errorf("invalid cursor value")
		}
		p.Cursor = &t
	}

	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			return p, fmt.Errorf("limit must be a positive integer")
		}
		if n > maxPageLimit {
			n = maxPageLimit
		}
		p.Limit = n
	}

	return p, nil
}

// encodeCursor encodes a time.Time into a base64 opaque cursor string.
func encodeCursor(t time.Time) string {
	return base64.URLEncoding.EncodeToString([]byte(t.UTC().Format(time.RFC3339Nano)))
}

// respondPaginatedSlice writes a cursor-paginated list response. Repositories
// fetch limit+1 rows so the handler can detect a further page; this trims the
// slice back to limit, derives the next cursor from the last returned item's
// timestamp (via createdAt), and emits the standard paginated envelope. It
// replaces the identical hasMore/nextCursor tail that every list handler had.
func respondPaginatedSlice[T any](w http.ResponseWriter, r *http.Request, status int, items []T, limit int, createdAt func(T) time.Time) {
	hasMore := len(items) > limit
	var nextCursor string
	if hasMore {
		items = items[:limit]
		nextCursor = encodeCursor(createdAt(items[len(items)-1]))
	}
	respondPaginated(w, r, status, items, nextCursor, hasMore)
}
