package cluster

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// ClusterHealth represents the aggregated health status across all cluster nodes.
type ClusterHealth struct {
	Healthy     bool         `json:"healthy"`
	TotalNodes  int          `json:"total_nodes"`
	ActiveNodes int          `json:"active_nodes"`
	DeadNodes   int          `json:"dead_nodes"`
	LeaderNode  string       `json:"leader_node,omitempty"`
	NodeHealths []NodeHealth `json:"nodes"`
}

// NodeHealth represents the health of a single cluster node.
type NodeHealth struct {
	Name          string `json:"name"`
	Status        string `json:"status"`        // from cluster_nodes table
	APIReachable  bool   `json:"api_reachable"` // live health check
	LastHeartbeat string `json:"last_heartbeat"`
	Role          string `json:"role"`
}

// HealthChecker performs cross-node health checks.
type HealthChecker struct {
	nodeMgr    *NodeManager
	logger     *slog.Logger
	httpClient *http.Client
}

// NewHealthChecker creates a new cluster health checker.
func NewHealthChecker(nodeMgr *NodeManager, logger *slog.Logger) *HealthChecker {
	return &HealthChecker{
		nodeMgr: nodeMgr,
		logger:  logger,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// Check performs a health check on all cluster nodes.
func (h *HealthChecker) Check(ctx context.Context) (*ClusterHealth, error) {
	nodes, err := h.nodeMgr.ListNodes(ctx)
	if err != nil {
		return nil, fmt.Errorf("list nodes for health check: %w", err)
	}

	leader, _ := h.nodeMgr.GetLeader(ctx)

	health := &ClusterHealth{
		Healthy:    true,
		TotalNodes: len(nodes),
	}

	if leader != nil {
		health.LeaderNode = leader.Name
	}

	for _, node := range nodes {
		nh := NodeHealth{
			Name:          node.Name,
			Status:        string(node.Status),
			Role:          string(node.Role),
			LastHeartbeat: node.LastHeartbeat.Format(time.RFC3339),
		}

		// Live health check via HTTP.
		nh.APIReachable = h.checkNodeAPI(ctx, node)

		switch NodeStatus(node.Status) {
		case StatusActive:
			health.ActiveNodes++
		case StatusDead:
			health.DeadNodes++
			health.Healthy = false
		}

		if !nh.APIReachable && NodeStatus(node.Status) == StatusActive {
			health.Healthy = false
		}

		health.NodeHealths = append(health.NodeHealths, nh)
	}

	// No leader = unhealthy.
	if leader == nil && len(nodes) > 0 {
		health.Healthy = false
	}

	return health, nil
}

func (h *HealthChecker) checkNodeAPI(ctx context.Context, node Node) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, node.APIAddr+"/api/v1/health", nil)
	if err != nil {
		return false
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == 200
}
