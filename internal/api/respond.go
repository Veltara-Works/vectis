package api

import (
	"encoding/json"
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
	RequestID string    `json:"request_id"`
	Timestamp time.Time `json:"timestamp"`
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
	json.NewEncoder(w).Encode(resp)
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
	json.NewEncoder(w).Encode(resp)
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
	json.NewEncoder(w).Encode(resp)
}

func decodeJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(v)
}
