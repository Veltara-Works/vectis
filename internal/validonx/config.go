package validonx

import (
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Veltara-Works/vectis/internal/config"
)

// Setup initialises the ValidonX client and feature-gate service from the
// application's secrets configuration. If ValidonX is not configured, both
// the client and the gate service are returned in a no-op / free-tier state.
//
// Usage:
//
//	client, gate := validonx.Setup(secrets, db, logger)
//	// client may be nil — always check with client.Configured()
//	// gate.FeatureGate("feature_name") is safe to use in middleware chains
func Setup(secrets *config.VectisSecrets, db *pgxpool.Pool, logger *slog.Logger) (*Client, *FeatureGateService) {
	var vxSecrets *config.ValidonXSecrets
	if secrets != nil {
		vxSecrets = secrets.ValidonX
	}

	client := NewClient(vxSecrets, logger.With("component", "validonx"))
	gate := NewFeatureGateService(client, db, logger.With("component", "validonx.gate"))

	if client != nil {
		logger.Info("validonx licensing configured",
			"base_url", vxSecrets.BaseURL,
			"tenant_id", vxSecrets.TenantID,
			"server_id", vxSecrets.ServerID,
		)
	} else {
		logger.Info("validonx licensing not configured — running in free-tier mode")
	}

	return client, gate
}
