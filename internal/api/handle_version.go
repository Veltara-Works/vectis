package api

import (
	"net/http"
	"runtime"

	"github.com/Veltara-Works/vectis/internal/version"
)

type versionResponse struct {
	Version   string `json:"version"`
	GoVersion string `json:"go_version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	respond(w, r, http.StatusOK, versionResponse{
		Version:   version.Version,
		GoVersion: runtime.Version(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
	})
}
