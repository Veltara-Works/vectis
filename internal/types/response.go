package types

import "time"

// APIResponse is the standard envelope for all API responses.
type APIResponse struct {
	Data  any          `json:"data,omitempty"`
	Error *APIError    `json:"error,omitempty"`
	Meta  ResponseMeta `json:"meta"`
}

// APIError carries structured error information.
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details any    `json:"details,omitempty"`
}

// ResponseMeta holds per-request metadata.
type ResponseMeta struct {
	RequestID string    `json:"request_id"`
	Timestamp time.Time `json:"timestamp"`
}

// NewSuccessResponse creates an APIResponse for a successful operation.
func NewSuccessResponse(data any, requestID string) APIResponse {
	return APIResponse{
		Data: data,
		Meta: ResponseMeta{
			RequestID: requestID,
			Timestamp: time.Now().UTC(),
		},
	}
}

// NewErrorResponse creates an APIResponse for a failed operation.
func NewErrorResponse(code string, message string, requestID string) APIResponse {
	return APIResponse{
		Error: &APIError{
			Code:    code,
			Message: message,
		},
		Meta: ResponseMeta{
			RequestID: requestID,
			Timestamp: time.Now().UTC(),
		},
	}
}
