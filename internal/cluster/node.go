package cluster

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Veltara-Works/vectis/internal/config"
	"github.com/Veltara-Works/vectis/internal/types"
)

// NodeRole describes the role of a cluster node.
type NodeRole string

const (
	RoleLeader  NodeRole = "leader"
	RoleWorker  NodeRole = "worker"
	RoleStandby NodeRole = "standby"
)

// NodeStatus describes the status of a cluster node.
type NodeStatus string

const (
	StatusJoining  NodeStatus = "joining"
	StatusActive   NodeStatus = "active"
	StatusDraining NodeStatus = "draining"
	StatusDead     NodeStatus = "dead"
)

// Node represents a registered cluster node.
type Node struct {
	ID            string          `json:"id"`
	Name          string          `json:"name"`
	AdvertiseAddr string          `json:"advertise_addr"`
	APIAddr       string          `json:"api_addr"`
	Role          NodeRole        `json:"role"`
	Status        NodeStatus      `json:"status"`
	Services      []string        `json:"services"`
	Metadata      json.RawMessage `json:"metadata,omitempty"`
	LastHeartbeat time.Time       `json:"last_heartbeat"`
	JoinedAt      time.Time       `json:"joined_at"`
}

// NodeManager handles node registration, heartbeats, and leader election.
type NodeManager struct {
	mu     sync.RWMutex
	db     *pgxpool.Pool
	cfg    config.ClusterConfig
	logger *slog.Logger

	nodeID   string
	isLeader bool
	stopCh   chan struct{}
}

// NewNodeManager creates a new cluster node manager.
func NewNodeManager(db *pgxpool.Pool, cfg config.ClusterConfig, logger *slog.Logger) *NodeManager {
	return &NodeManager{
		db:     db,
		cfg:    cfg,
		logger: logger,
		stopCh: make(chan struct{}),
	}
}

// Register adds this node to the cluster and starts the heartbeat loop.
// Returns the node ID assigned to this node.
func (m *NodeManager) Register(ctx context.Context) (string, error) {
	nodeName := m.cfg.NodeName
	if nodeName == "" {
		hostname, err := os.Hostname()
		if err != nil {
			nodeName = "node-" + types.NewUUIDv7()[:8]
		} else {
			nodeName = hostname
		}
	}

	nodeID := types.NewUUIDv7()
	now := time.Now().UTC()

	metadata := map[string]any{
		"hostname":   nodeName,
		"pid":        os.Getpid(),
		"started_at": now.Format(time.RFC3339),
	}
	metadataJSON, _ := json.Marshal(metadata)

	// Upsert — if node name already exists, update it (rejoin after crash).
	_, err := m.db.Exec(ctx,
		`INSERT INTO cluster_nodes (id, name, advertise_addr, api_addr, role, status, services, metadata, last_heartbeat, joined_at, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, 'worker', 'joining', $5, $6, $7, $7, $7, $7)
		 ON CONFLICT (name) DO UPDATE SET
		   advertise_addr = EXCLUDED.advertise_addr,
		   api_addr = EXCLUDED.api_addr,
		   status = 'joining',
		   services = EXCLUDED.services,
		   metadata = EXCLUDED.metadata,
		   last_heartbeat = EXCLUDED.last_heartbeat,
		   updated_at = EXCLUDED.updated_at`,
		nodeID, nodeName, m.cfg.AdvertiseAddr, m.apiAddr(),
		m.cfg.Services, metadataJSON, now,
	)
	if err != nil {
		return "", fmt.Errorf("register node: %w", err)
	}

	// If this was a rejoin (conflict), read back the actual ID.
	var actualID string
	err = m.db.QueryRow(ctx,
		`SELECT id FROM cluster_nodes WHERE name = $1`, nodeName,
	).Scan(&actualID)
	if err != nil {
		return "", fmt.Errorf("read node id: %w", err)
	}

	m.mu.Lock()
	m.nodeID = actualID
	m.mu.Unlock()

	// Transition to active.
	_, err = m.db.Exec(ctx,
		`UPDATE cluster_nodes SET status = 'active', updated_at = NOW() WHERE id = $1`, actualID)
	if err != nil {
		return "", fmt.Errorf("activate node: %w", err)
	}

	m.logger.Info("node registered",
		"node_id", actualID, "name", nodeName,
		"advertise_addr", m.cfg.AdvertiseAddr, "services", m.cfg.Services)

	return actualID, nil
}

// Start begins the heartbeat and leader election loops.
func (m *NodeManager) Start() {
	heartbeat := time.Duration(m.cfg.HeartbeatSec) * time.Second
	if heartbeat == 0 {
		heartbeat = 10 * time.Second
	}

	go func() {
		ticker := time.NewTicker(heartbeat)
		defer ticker.Stop()

		for {
			select {
			case <-m.stopCh:
				return
			case <-ticker.C:
				m.sendHeartbeat()
				m.tryLeaderElection()
				m.detectDeadNodes()
			}
		}
	}()
}

// Stop signals the node manager to shut down and marks the node as draining.
func (m *NodeManager) Stop() {
	m.logger.Info("stopping node manager")
	close(m.stopCh)

	m.mu.RLock()
	nodeID := m.nodeID
	m.mu.RUnlock()

	if nodeID != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		m.db.Exec(ctx,
			`UPDATE cluster_nodes SET status = 'draining', updated_at = NOW() WHERE id = $1`, nodeID)

		// Release leadership if we're the leader.
		if m.IsLeader() {
			m.db.Exec(ctx, `DELETE FROM cluster_leader WHERE node_id = $1`, nodeID)
		}
	}
}

// NodeID returns this node's ID.
func (m *NodeManager) NodeID() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.nodeID
}

// IsLeader returns true if this node is the current cluster leader.
func (m *NodeManager) IsLeader() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.isLeader
}

// ListNodes returns all registered cluster nodes.
func (m *NodeManager) ListNodes(ctx context.Context) ([]Node, error) {
	rows, err := m.db.Query(ctx,
		`SELECT id, name, advertise_addr, api_addr, role, status, services, metadata, last_heartbeat, joined_at
		 FROM cluster_nodes ORDER BY joined_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}
	defer rows.Close()

	var nodes []Node
	for rows.Next() {
		var n Node
		if err := rows.Scan(&n.ID, &n.Name, &n.AdvertiseAddr, &n.APIAddr, &n.Role, &n.Status,
			&n.Services, &n.Metadata, &n.LastHeartbeat, &n.JoinedAt); err != nil {
			return nil, fmt.Errorf("scan node: %w", err)
		}
		nodes = append(nodes, n)
	}
	return nodes, nil
}

// GetLeader returns the current cluster leader, or nil if no leader.
func (m *NodeManager) GetLeader(ctx context.Context) (*Node, error) {
	var n Node
	err := m.db.QueryRow(ctx,
		`SELECT cn.id, cn.name, cn.advertise_addr, cn.api_addr, cn.role, cn.status, cn.services, cn.metadata, cn.last_heartbeat, cn.joined_at
		 FROM cluster_leader cl JOIN cluster_nodes cn ON cn.id = cl.node_id
		 WHERE cl.lease_expires > NOW()`).Scan(
		&n.ID, &n.Name, &n.AdvertiseAddr, &n.APIAddr, &n.Role, &n.Status,
		&n.Services, &n.Metadata, &n.LastHeartbeat, &n.JoinedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get leader: %w", err)
	}
	return &n, nil
}

// RemoveNode removes a node from the cluster (admin action).
func (m *NodeManager) RemoveNode(ctx context.Context, nodeID string) error {
	_, err := m.db.Exec(ctx, `DELETE FROM cluster_nodes WHERE id = $1`, nodeID)
	if err != nil {
		return fmt.Errorf("remove node: %w", err)
	}
	return nil
}

func (m *NodeManager) sendHeartbeat() {
	m.mu.RLock()
	nodeID := m.nodeID
	m.mu.RUnlock()

	if nodeID == "" {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := m.db.Exec(ctx,
		`UPDATE cluster_nodes SET last_heartbeat = NOW(), updated_at = NOW() WHERE id = $1`, nodeID)
	if err != nil {
		m.logger.Error("heartbeat failed", "error", err)
	}

	// If we're the leader, renew the lease.
	if m.IsLeader() {
		leaseDuration := time.Duration(m.cfg.LeaderLeaseSec) * time.Second
		if leaseDuration == 0 {
			leaseDuration = 30 * time.Second
		}
		_, err := m.db.Exec(ctx,
			`UPDATE cluster_leader SET lease_expires = NOW() + $1::interval WHERE node_id = $2`,
			fmt.Sprintf("%d seconds", int(leaseDuration.Seconds())), nodeID)
		if err != nil {
			m.logger.Error("leader lease renewal failed", "error", err)
		}
	}
}

func (m *NodeManager) tryLeaderElection() {
	m.mu.RLock()
	nodeID := m.nodeID
	m.mu.RUnlock()

	if nodeID == "" {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	leaseDuration := time.Duration(m.cfg.LeaderLeaseSec) * time.Second
	if leaseDuration == 0 {
		leaseDuration = 30 * time.Second
	}
	leaseExpires := time.Now().UTC().Add(leaseDuration)

	// Try to claim leadership if no valid leader exists.
	// Uses INSERT ... ON CONFLICT with a WHERE clause on lease expiry.
	result, err := m.db.Exec(ctx,
		`INSERT INTO cluster_leader (id, node_id, elected_at, lease_expires, term)
		 VALUES (1, $1, NOW(), $2, 1)
		 ON CONFLICT (id) DO UPDATE SET
		   node_id = EXCLUDED.node_id,
		   elected_at = NOW(),
		   lease_expires = EXCLUDED.lease_expires,
		   term = cluster_leader.term + 1
		 WHERE cluster_leader.lease_expires < NOW()`,
		nodeID, leaseExpires,
	)
	if err != nil {
		m.logger.Error("leader election failed", "error", err)
		return
	}

	rowsAffected := result.RowsAffected()

	if rowsAffected > 0 {
		m.mu.Lock()
		wasLeader := m.isLeader
		m.isLeader = true
		m.mu.Unlock()

		if !wasLeader {
			m.logger.Info("elected as cluster leader", "node_id", nodeID)
			// Update node role.
			m.db.Exec(ctx,
				`UPDATE cluster_nodes SET role = 'leader', updated_at = NOW() WHERE id = $1`, nodeID)
		}
		return
	}

	// Check if we are still the leader (our lease hasn't expired).
	var leaderNodeID string
	err = m.db.QueryRow(ctx,
		`SELECT node_id FROM cluster_leader WHERE lease_expires > NOW()`).Scan(&leaderNodeID)
	if err == nil {
		m.mu.Lock()
		wasLeader := m.isLeader
		m.isLeader = (leaderNodeID == nodeID)
		m.mu.Unlock()

		if wasLeader && leaderNodeID != nodeID {
			m.logger.Warn("lost cluster leadership", "new_leader", leaderNodeID)
			m.db.Exec(ctx,
				`UPDATE cluster_nodes SET role = 'worker', updated_at = NOW() WHERE id = $1`, nodeID)
		}
	}
}

func (m *NodeManager) detectDeadNodes() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Mark nodes as dead if no heartbeat for 3x the heartbeat interval.
	deadThreshold := time.Duration(m.cfg.HeartbeatSec*3) * time.Second
	if deadThreshold == 0 {
		deadThreshold = 30 * time.Second
	}
	cutoff := time.Now().UTC().Add(-deadThreshold)

	result, err := m.db.Exec(ctx,
		`UPDATE cluster_nodes SET status = 'dead', updated_at = NOW()
		 WHERE status = 'active' AND last_heartbeat < $1`, cutoff)
	if err != nil {
		m.logger.Error("detect dead nodes failed", "error", err)
		return
	}

	if result.RowsAffected() > 0 {
		m.logger.Warn("detected dead nodes", "count", result.RowsAffected())
	}
}

func (m *NodeManager) apiAddr() string {
	// Derive API address from advertise addr or config.
	if m.cfg.AdvertiseAddr != "" {
		return "https://" + m.cfg.AdvertiseAddr
	}
	return "https://localhost:8080"
}
