package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

// handleClusterStatus returns the cluster state — nodes, leader, health.
func (s *Server) handleClusterStatus(w http.ResponseWriter, r *http.Request) {
	if s.clusterHealth == nil {
		respondError(w, r, http.StatusServiceUnavailable, "CLUSTER_DISABLED",
			"Cluster mode is not enabled")
		return
	}

	health, err := s.clusterHealth.Check(r.Context())
	if err != nil {
		s.logger.Error("cluster health check failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to check cluster health")
		return
	}

	respond(w, r, http.StatusOK, health)
}

// handleListClusterNodes returns all registered cluster nodes.
func (s *Server) handleListClusterNodes(w http.ResponseWriter, r *http.Request) {
	if s.nodeMgr == nil {
		respondError(w, r, http.StatusServiceUnavailable, "CLUSTER_DISABLED",
			"Cluster mode is not enabled")
		return
	}

	nodes, err := s.nodeMgr.ListNodes(r.Context())
	if err != nil {
		s.logger.Error("list cluster nodes failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list nodes")
		return
	}

	respond(w, r, http.StatusOK, nodes)
}

// handleRemoveClusterNode removes a dead/draining node from the cluster.
func (s *Server) handleRemoveClusterNode(w http.ResponseWriter, r *http.Request) {
	if s.nodeMgr == nil {
		respondError(w, r, http.StatusServiceUnavailable, "CLUSTER_DISABLED",
			"Cluster mode is not enabled")
		return
	}

	nodeID := chi.URLParam(r, "nodeID")
	if nodeID == "" {
		respondError(w, r, http.StatusBadRequest, "MISSING_ID", "Node ID is required")
		return
	}

	if err := s.nodeMgr.RemoveNode(r.Context(), nodeID); err != nil {
		s.logger.Error("remove cluster node failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to remove node")
		return
	}

	adminID := getAdminID(r.Context())
	ip := clientIP(r)
	s.audit.Log(r.Context(), &adminID, "cluster.remove_node", "cluster_node", &nodeID, nil, &ip)

	respond(w, r, http.StatusOK, map[string]string{"status": "removed"})
}

// handleClusterRollingUpdate initiates a rolling update across all nodes.
func (s *Server) handleClusterRollingUpdate(w http.ResponseWriter, r *http.Request) {
	if s.rollingCoord == nil {
		respondError(w, r, http.StatusServiceUnavailable, "CLUSTER_DISABLED",
			"Cluster mode is not enabled")
		return
	}

	adminID := getAdminID(r.Context())
	op, err := s.rollingCoord.StartRollingUpdate(r.Context(), adminID, nil)
	if err != nil {
		s.logger.Error("start rolling update failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	ip := clientIP(r)
	s.audit.Log(r.Context(), &adminID, "cluster.rolling_update", "cluster_operation", &op.ID, nil, &ip)

	respond(w, r, http.StatusAccepted, op)
}

// handleClusterRollingRollback initiates a rolling rollback across all nodes.
func (s *Server) handleClusterRollingRollback(w http.ResponseWriter, r *http.Request) {
	if s.rollingCoord == nil {
		respondError(w, r, http.StatusServiceUnavailable, "CLUSTER_DISABLED",
			"Cluster mode is not enabled")
		return
	}

	adminID := getAdminID(r.Context())
	op, err := s.rollingCoord.StartRollingRollback(r.Context(), adminID)
	if err != nil {
		s.logger.Error("start rolling rollback failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	ip := clientIP(r)
	s.audit.Log(r.Context(), &adminID, "cluster.rolling_rollback", "cluster_operation", &op.ID, nil, &ip)

	respond(w, r, http.StatusAccepted, op)
}

// handleListClusterOperations returns recent cluster operations.
func (s *Server) handleListClusterOperations(w http.ResponseWriter, r *http.Request) {
	if s.rollingCoord == nil {
		respondError(w, r, http.StatusServiceUnavailable, "CLUSTER_DISABLED",
			"Cluster mode is not enabled")
		return
	}

	ops, err := s.rollingCoord.ListOperations(r.Context(), 20)
	if err != nil {
		s.logger.Error("list cluster operations failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list operations")
		return
	}

	respond(w, r, http.StatusOK, ops)
}

// handleGetClusterOperation returns a single cluster operation by ID.
func (s *Server) handleGetClusterOperation(w http.ResponseWriter, r *http.Request) {
	if s.rollingCoord == nil {
		respondError(w, r, http.StatusServiceUnavailable, "CLUSTER_DISABLED",
			"Cluster mode is not enabled")
		return
	}

	opID := chi.URLParam(r, "operationID")
	if opID == "" {
		respondError(w, r, http.StatusBadRequest, "MISSING_ID", "Operation ID is required")
		return
	}

	op, err := s.rollingCoord.GetOperation(r.Context(), opID)
	if err != nil {
		s.logger.Error("get cluster operation failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get operation")
		return
	}

	respond(w, r, http.StatusOK, op)
}
