package api

import (
	"net/http"

	"github.com/Veltara-Works/vectis/internal/branding"
)

// brandingResponse is the wire shape returned by GET / PUT / DELETE /branding.
// `effective` is what the chrome should actually render (defaults filled in);
// the raw fields above it show what the operator saved (for the form).
type brandingResponse struct {
	ProductName  string         `json:"product_name"`
	PrimaryColor string         `json:"primary_color"`
	LogoURL      string         `json:"logo_url"`
	FromDB       bool           `json:"from_db"`
	Effective    effectiveBrand `json:"effective"`
}

type effectiveBrand struct {
	ProductName  string `json:"product_name"`
	PrimaryColor string `json:"primary_color"`
	LogoURL      string `json:"logo_url"`
}

func (s *Server) brandingResponseFor(cfg branding.Config) brandingResponse {
	eff := cfg.Effective()
	return brandingResponse{
		ProductName:  cfg.ProductName,
		PrimaryColor: cfg.PrimaryColor,
		LogoURL:      cfg.LogoURL,
		FromDB:       cfg.FromDB,
		Effective: effectiveBrand{
			ProductName:  eff.ProductName,
			PrimaryColor: eff.PrimaryColor,
			LogoURL:      eff.LogoURL,
		},
	}
}

// handleGetBranding returns the active branding (defaults if empty). Always
// safe to call — the chrome on Free installs hits this on every page load.
// Auth (super_admin) is enforced at the route level.
func (s *Server) handleGetBranding(w http.ResponseWriter, r *http.Request) {
	cfg, err := branding.LoadConfig(r.Context(), s.db)
	if err != nil {
		s.logger.Error("load branding config failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load branding")
		return
	}
	respond(w, r, http.StatusOK, s.brandingResponseFor(cfg))
}

type setBrandingRequest struct {
	ProductName  string `json:"product_name"`
	PrimaryColor string `json:"primary_color"`
	LogoURL      string `json:"logo_url"`
}

// handleSetBranding upserts the singleton row. Pro-feature gate is applied
// at the route level (FeatureGate(custom_branding)); this handler trusts
// that any caller that reaches it is entitled.
func (s *Server) handleSetBranding(w http.ResponseWriter, r *http.Request) {
	var req setBrandingRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, r, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON request body")
		return
	}

	cfg := branding.Config{
		ProductName:  req.ProductName,
		PrimaryColor: req.PrimaryColor,
		LogoURL:      req.LogoURL,
	}
	if err := cfg.Validate(); err != nil {
		respondError(w, r, http.StatusBadRequest, "INVALID_BRANDING", err.Error())
		return
	}

	adminID := getAdminID(r.Context())
	if err := branding.SaveConfig(r.Context(), s.db, s.logger, cfg, adminID); err != nil {
		s.logger.Error("save branding config failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to save branding")
		return
	}

	cfg.FromDB = true
	ip := clientIP(r)
	s.audit.Log(r.Context(), &adminID, "branding.update", "branding", nil,
		map[string]string{"product_name": cfg.ProductName, "has_logo": boolStr(cfg.LogoURL != "")}, &ip)

	respond(w, r, http.StatusOK, s.brandingResponseFor(cfg))
}

// handleDeleteBranding clears the singleton row, reverting the install to
// defaults. Pro-feature gate is applied at the route level.
func (s *Server) handleDeleteBranding(w http.ResponseWriter, r *http.Request) {
	if err := branding.ClearConfig(r.Context(), s.db, s.logger); err != nil {
		s.logger.Error("clear branding config failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to clear branding")
		return
	}

	adminID := getAdminID(r.Context())
	ip := clientIP(r)
	s.audit.Log(r.Context(), &adminID, "branding.clear", "branding", nil, nil, &ip)

	respond(w, r, http.StatusOK, s.brandingResponseFor(branding.Config{}))
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
