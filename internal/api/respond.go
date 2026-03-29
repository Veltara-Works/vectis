package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"
)

// apiResponse is the standard JSON envelope for all API responses.
type apiResponse struct {
	Data  any        `json:"data,omitempty"`
	Error *apiError  `json:"error,omitempty"`
	Meta  apiMeta    `json:"meta"`
}

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details any    `json:"details,omitempty"`
}

type apiMeta struct {
	RequestID  string          `json:"request_id"`
	Timestamp  time.Time       `json:"timestamp"`
	Pagination *paginationMeta `json:"pagination,omitempty"`
}

func respond(w http.ResponseWriter, r *http.Request, status int, data any) {
	resp := apiResponse{
		Data: data,
		Meta: apiMeta{
			RequestID: getRequestID(r.Context()),
			Timestamp: time.Now().UTC(),
		},
	}
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Error("failed to encode response", "error", err, "request_id", getRequestID(r.Context()))
	}
}

func respondError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	resp := apiResponse{
		Error: &apiError{
			Code:    code,
			Message: message,
		},
		Meta: apiMeta{
			RequestID: getRequestID(r.Context()),
			Timestamp: time.Now().UTC(),
		},
	}
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Error("failed to encode error response", "error", err, "request_id", getRequestID(r.Context()))
	}
}

func respondErrorWithDetails(w http.ResponseWriter, r *http.Request, status int, code, message string, details any) {
	resp := apiResponse{
		Error: &apiError{
			Code:    code,
			Message: message,
			Details: details,
		},
		Meta: apiMeta{
			RequestID: getRequestID(r.Context()),
			Timestamp: time.Now().UTC(),
		},
	}
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Error("failed to encode error response", "error", err, "request_id", getRequestID(r.Context()))
	}
}

func respondPaginated(w http.ResponseWriter, r *http.Request, status int, data any, nextCursor string, hasMore bool) {
	resp := apiResponse{
		Data: data,
		Meta: apiMeta{
			RequestID: getRequestID(r.Context()),
			Timestamp: time.Now().UTC(),
			Pagination: &paginationMeta{
				NextCursor: nextCursor,
				HasMore:    hasMore,
			},
		},
	}
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Error("failed to encode paginated response", "error", err, "request_id", getRequestID(r.Context()))
	}
}

// maxBodySize is the maximum size of a JSON request body (1 MB).
const maxBodySize = 1 << 20

func decodeJSON(r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, maxBodySize)
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(v)
}
