package cluster

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Veltara-Works/vectis/internal/types"
)

// OperationType describes the type of cluster-wide operation.
type OperationType string

const (
	OpRollingUpdate   OperationType = "rolling_update"
	OpRollingRollback OperationType = "rolling_rollback"
	OpConfigSync      OperationType = "config_sync"
)

// OperationStatus describes the status of a cluster operation.
type OperationStatus string

const (
	OpPending    OperationStatus = "pending"
	OpInProgress OperationStatus = "in_progress"
	OpCompleted  OperationStatus = "completed"
	OpFailed     OperationStatus = "failed"
)

// ClusterOperation tracks a multi-node operation.
type ClusterOperation struct {
	ID            string            `json:"id"`
	OperationType string            `json:"operation_type"`
	Status        string            `json:"status"`
	InitiatedBy   *string           `json:"initiated_by,omitempty"`
	PlanSummary   json.RawMessage   `json:"plan_summary,omitempty"`
	NodeStatuses  map[string]string `json:"node_statuses"`
	ErrorMessage  *string           `json:"error_message,omitempty"`
	StartedAt     time.Time         `json:"started_at"`
	CompletedAt   *time.Time        `json:"completed_at,omitempty"`
}

// RollingCoordinator manages rolling updates and rollbacks across cluster nodes.
// Only the leader node runs the coordinator.
type RollingCoordinator struct {
	db         *pgxpool.Pool
	nodeMgr    *NodeManager
	logger     *slog.Logger
	httpClient *http.Client
}

// NewRollingCoordinator creates a new rolling update coordinator.
func NewRollingCoordinator(db *pgxpool.Pool, nodeMgr *NodeManager, logger *slog.Logger) *RollingCoordinator {
	return &RollingCoordinator{
		db:      db,
		nodeMgr: nodeMgr,
		logger:  logger,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// StartRollingUpdate initiates a rolling update across all active nodes.
// The update proceeds one node at a time with health checks between each.
func (c *RollingCoordinator) StartRollingUpdate(ctx context.Context, adminID string, planSummary json.RawMessage) (*ClusterOperation, error) {
	if !c.nodeMgr.IsLeader() {
		return nil, fmt.Errorf("only the leader node can initiate rolling updates")
	}

	// Get all active nodes.
	nodes, err := c.nodeMgr.ListNodes(ctx)
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}

	var activeNodes []Node
	for _, n := range nodes {
		if NodeStatus(n.Status) == StatusActive {
			activeNodes = append(activeNodes, n)
		}
	}
	if len(activeNodes) == 0 {
		return nil, fmt.Errorf("no active nodes in cluster")
	}

	// Create operation record.
	opID := types.NewUUIDv7()
	nodeStatuses := make(map[string]string)
	for _, n := range activeNodes {
		nodeStatuses[n.Name] = "pending"
	}
	nodeStatusesJSON, _ := json.Marshal(nodeStatuses)

	// Insert only if no operation is already in progress — atomically, via
	// WHERE NOT EXISTS, so it is free of the check-then-insert race. Without this
	// a double-submit, or a brief dual-leader window during handoff (IsLeader()
	// is a cached bool), would each spawn an executeRolling goroutine that drives
	// every node through apply/restart concurrently, defeating the one-at-a-time
	// guarantee and risking a simultaneous restart of the whole cluster (CLUS-1).
	tag, err := c.db.Exec(ctx,
		`INSERT INTO cluster_operations (id, operation_type, status, initiated_by, plan_summary, node_statuses, started_at)
		 SELECT $1, $2, 'in_progress', $3, $4, $5, NOW()
		 WHERE NOT EXISTS (SELECT 1 FROM cluster_operations WHERE status = 'in_progress')`,
		opID, string(OpRollingUpdate), adminID, planSummary, nodeStatusesJSON,
	)
	if err != nil {
		return nil, fmt.Errorf("create operation: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return nil, fmt.Errorf("a rolling operation is already in progress")
	}

	// Execute rolling update in background.
	go c.executeRolling(opID, activeNodes, OpRollingUpdate)

	return &ClusterOperation{
		ID:            opID,
		OperationType: string(OpRollingUpdate),
		Status:        string(OpInProgress),
		NodeStatuses:  nodeStatuses,
		StartedAt:     time.Now().UTC(),
	}, nil
}

// StartRollingRollback initiates a rolling rollback across all active nodes.
func (c *RollingCoordinator) StartRollingRollback(ctx context.Context, adminID string) (*ClusterOperation, error) {
	if !c.nodeMgr.IsLeader() {
		return nil, fmt.Errorf("only the leader node can initiate rolling rollbacks")
	}

	nodes, err := c.nodeMgr.ListNodes(ctx)
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}

	var activeNodes []Node
	for _, n := range nodes {
		if NodeStatus(n.Status) == StatusActive {
			activeNodes = append(activeNodes, n)
		}
	}

	opID := types.NewUUIDv7()
	nodeStatuses := make(map[string]string)
	for _, n := range activeNodes {
		nodeStatuses[n.Name] = "pending"
	}
	nodeStatusesJSON, _ := json.Marshal(nodeStatuses)

	// Atomic in-progress guard — see StartRollingUpdate (CLUS-1).
	tag, err := c.db.Exec(ctx,
		`INSERT INTO cluster_operations (id, operation_type, status, initiated_by, node_statuses, started_at)
		 SELECT $1, $2, 'in_progress', $3, $4, NOW()
		 WHERE NOT EXISTS (SELECT 1 FROM cluster_operations WHERE status = 'in_progress')`,
		opID, string(OpRollingRollback), adminID, nodeStatusesJSON,
	)
	if err != nil {
		return nil, fmt.Errorf("create operation: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return nil, fmt.Errorf("a rolling operation is already in progress")
	}

	go c.executeRolling(opID, activeNodes, OpRollingRollback)

	return &ClusterOperation{
		ID:            opID,
		OperationType: string(OpRollingRollback),
		Status:        string(OpInProgress),
		NodeStatuses:  nodeStatuses,
		StartedAt:     time.Now().UTC(),
	}, nil
}

// GetOperation retrieves a cluster operation by ID.
func (c *RollingCoordinator) GetOperation(ctx context.Context, operationID string) (*ClusterOperation, error) {
	var op ClusterOperation
	var nodeStatusesJSON []byte
	err := c.db.QueryRow(ctx,
		`SELECT id, operation_type, status, initiated_by, plan_summary, node_statuses, error_message, started_at, completed_at
		 FROM cluster_operations WHERE id = $1`, operationID,
	).Scan(&op.ID, &op.OperationType, &op.Status, &op.InitiatedBy, &op.PlanSummary,
		&nodeStatusesJSON, &op.ErrorMessage, &op.StartedAt, &op.CompletedAt)
	if err != nil {
		return nil, fmt.Errorf("get operation: %w", err)
	}
	json.Unmarshal(nodeStatusesJSON, &op.NodeStatuses)
	return &op, nil
}

// ListOperations returns recent cluster operations.
func (c *RollingCoordinator) ListOperations(ctx context.Context, limit int) ([]ClusterOperation, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := c.db.Query(ctx,
		`SELECT id, operation_type, status, initiated_by, plan_summary, node_statuses, error_message, started_at, completed_at
		 FROM cluster_operations ORDER BY started_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list operations: %w", err)
	}
	defer rows.Close()

	var ops []ClusterOperation
	for rows.Next() {
		var op ClusterOperation
		var nodeStatusesJSON []byte
		if err := rows.Scan(&op.ID, &op.OperationType, &op.Status, &op.InitiatedBy, &op.PlanSummary,
			&nodeStatusesJSON, &op.ErrorMessage, &op.StartedAt, &op.CompletedAt); err != nil {
			return nil, fmt.Errorf("scan operation: %w", err)
		}
		json.Unmarshal(nodeStatusesJSON, &op.NodeStatuses)
		ops = append(ops, op)
	}
	return ops, nil
}

// executeRolling runs the rolling operation node-by-node.
// Leader node is updated last to maintain coordination.
func (c *RollingCoordinator) executeRolling(opID string, nodes []Node, opType OperationType) {
	ctx := context.Background()

	// Sort: workers first, leader last.
	leaderID := c.nodeMgr.NodeID()
	var ordered []Node
	var leaderNode *Node
	for i := range nodes {
		if nodes[i].ID == leaderID {
			leaderNode = &nodes[i]
		} else {
			ordered = append(ordered, nodes[i])
		}
	}
	if leaderNode != nil {
		ordered = append(ordered, *leaderNode)
	}

	for _, node := range ordered {
		c.logger.Info("rolling operation: processing node",
			"operation_id", opID, "node", node.Name, "type", string(opType))

		// Update node status to in_progress.
		c.updateNodeStatus(ctx, opID, node.Name, "in_progress")

		var err error
		if node.ID == leaderID {
			// Local operation — trigger orchestrator directly.
			err = c.triggerLocalOperation(ctx, opType)
		} else {
			// Remote operation — call node's API.
			err = c.triggerRemoteOperation(ctx, node, opType)
		}

		if err != nil {
			c.logger.Error("rolling operation failed on node",
				"operation_id", opID, "node", node.Name, "error", err)
			c.updateNodeStatus(ctx, opID, node.Name, "failed")
			c.completeOperation(ctx, opID, OpFailed, err.Error())
			return
		}

		// Wait for health check to pass.
		if err := c.waitForNodeHealth(ctx, node); err != nil {
			c.logger.Error("health check failed after operation",
				"operation_id", opID, "node", node.Name, "error", err)
			c.updateNodeStatus(ctx, opID, node.Name, "health_failed")
			c.completeOperation(ctx, opID, OpFailed, "health check failed on "+node.Name+": "+err.Error())
			return
		}

		c.updateNodeStatus(ctx, opID, node.Name, "completed")
		c.logger.Info("rolling operation: node completed",
			"operation_id", opID, "node", node.Name)
	}

	c.completeOperation(ctx, opID, OpCompleted, "")
	c.logger.Info("rolling operation completed", "operation_id", opID)
}

func (c *RollingCoordinator) triggerLocalOperation(ctx context.Context, opType OperationType) error {
	// In a real implementation, this calls the local orchestrator's Apply or Rollback.
	// The orchestrator is in the same process or reachable at localhost.
	endpoint := "/api/v1/orchestrator/apply"
	if opType == OpRollingRollback {
		endpoint = "/api/v1/orchestrator/rollback"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost:8080"+endpoint, nil)
	if err != nil {
		return fmt.Errorf("build local request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("local operation request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("local operation returned status %d", resp.StatusCode)
	}
	return nil
}

func (c *RollingCoordinator) triggerRemoteOperation(ctx context.Context, node Node, opType OperationType) error {
	endpoint := "/api/v1/orchestrator/apply"
	if opType == OpRollingRollback {
		endpoint = "/api/v1/orchestrator/rollback"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, node.APIAddr+endpoint, nil)
	if err != nil {
		return fmt.Errorf("build remote request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("remote operation request to %s: %w", node.Name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("remote operation on %s returned status %d", node.Name, resp.StatusCode)
	}
	return nil
}

func (c *RollingCoordinator) waitForNodeHealth(ctx context.Context, node Node) error {
	// Poll node health endpoint with timeout.
	timeout := 2 * time.Minute
	interval := 5 * time.Second
	deadline := time.Now().Add(timeout)

	healthURL := node.APIAddr + "/api/v1/health"

	for time.Now().Before(deadline) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
		if err != nil {
			return err
		}

		resp, err := c.httpClient.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return nil
			}
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
		}
	}

	return fmt.Errorf("health check timed out after %s", timeout)
}

func (c *RollingCoordinator) updateNodeStatus(ctx context.Context, opID, nodeName, status string) {
	// Read current statuses, update one, write back.
	var nodeStatusesJSON []byte
	c.db.QueryRow(ctx,
		`SELECT node_statuses FROM cluster_operations WHERE id = $1`, opID,
	).Scan(&nodeStatusesJSON)

	statuses := make(map[string]string)
	json.Unmarshal(nodeStatusesJSON, &statuses)
	statuses[nodeName] = status
	updated, _ := json.Marshal(statuses)

	c.db.Exec(ctx,
		`UPDATE cluster_operations SET node_statuses = $1 WHERE id = $2`, updated, opID)
}

func (c *RollingCoordinator) completeOperation(ctx context.Context, opID string, status OperationStatus, errMsg string) {
	var errPtr *string
	if errMsg != "" {
		errPtr = &errMsg
	}
	c.db.Exec(ctx,
		`UPDATE cluster_operations SET status = $1, error_message = $2, completed_at = NOW() WHERE id = $3`,
		string(status), errPtr, opID)
}
