package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Veltara-Works/vectis/internal/types"
)

// Admin represents an admin user.
type Admin struct {
	ID          string     `json:"id"`
	Email       string     `json:"email"`
	PasswordHash string   `json:"-"`
	TOTPSecret  *string    `json:"-"`
	TOTPEnabled bool       `json:"totp_enabled"`
	Role        string     `json:"role"`
	CreatedAt   time.Time  `json:"created_at"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
}

// AdminCreate holds fields for creating an admin.
type AdminCreate struct {
	Email        string
	PasswordHash string
	Role         string
}

// AdminUpdate holds fields for updating an admin.
type AdminUpdate struct {
	Email        *string
	PasswordHash *string
	TOTPSecret   *string
	TOTPEnabled  *bool
	Role         *string
}

// AdminRepo handles admin CRUD operations.
type AdminRepo struct {
	db *pgxpool.Pool
}

// NewAdminRepo creates a new admin repository.
func NewAdminRepo(db *pgxpool.Pool) *AdminRepo {
	return &AdminRepo{db: db}
}

// Create inserts a new admin.
func (r *AdminRepo) Create(ctx context.Context, input AdminCreate) (*Admin, error) {
	role := input.Role
	if role == "" {
		role = "admin"
	}

	a := &Admin{
		ID:           types.NewUUIDv7(),
		Email:        input.Email,
		PasswordHash: input.PasswordHash,
		TOTPEnabled:  false,
		Role:         role,
		CreatedAt:    time.Now().UTC(),
	}

	_, err := r.db.Exec(ctx,
		`INSERT INTO admins (id, email, password_hash, totp_enabled, role, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		a.ID, a.Email, a.PasswordHash, a.TOTPEnabled, a.Role, a.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("insert admin: %w", err)
	}
	return a, nil
}

// GetByID fetches an admin by UUID.
func (r *AdminRepo) GetByID(ctx context.Context, id string) (*Admin, error) {
	a := &Admin{}
	err := r.db.QueryRow(ctx,
		`SELECT id, email, password_hash, totp_secret, totp_enabled, role, created_at, last_login_at
		 FROM admins WHERE id = $1`, id,
	).Scan(&a.ID, &a.Email, &a.PasswordHash, &a.TOTPSecret, &a.TOTPEnabled, &a.Role, &a.CreatedAt, &a.LastLoginAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get admin: %w", err)
	}
	return a, nil
}

// GetByEmail fetches an admin by email.
func (r *AdminRepo) GetByEmail(ctx context.Context, email string) (*Admin, error) {
	a := &Admin{}
	err := r.db.QueryRow(ctx,
		`SELECT id, email, password_hash, totp_secret, totp_enabled, role, created_at, last_login_at
		 FROM admins WHERE email = $1`, email,
	).Scan(&a.ID, &a.Email, &a.PasswordHash, &a.TOTPSecret, &a.TOTPEnabled, &a.Role, &a.CreatedAt, &a.LastLoginAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get admin by email: %w", err)
	}
	return a, nil
}

// List returns all admins.
func (r *AdminRepo) List(ctx context.Context) ([]Admin, error) {
	rows, err := r.db.Query(ctx,
		`SELECT id, email, password_hash, totp_secret, totp_enabled, role, created_at, last_login_at
		 FROM admins ORDER BY email`)
	if err != nil {
		return nil, fmt.Errorf("list admins: %w", err)
	}
	defer rows.Close()

	var admins []Admin
	for rows.Next() {
		var a Admin
		if err := rows.Scan(&a.ID, &a.Email, &a.PasswordHash, &a.TOTPSecret, &a.TOTPEnabled, &a.Role, &a.CreatedAt, &a.LastLoginAt); err != nil {
			return nil, fmt.Errorf("scan admin: %w", err)
		}
		admins = append(admins, a)
	}
	return admins, nil
}

// Update modifies an admin's mutable fields.
func (r *AdminRepo) Update(ctx context.Context, id string, input AdminUpdate) (*Admin, error) {
	setClauses := []string{}
	args := []any{}
	argIdx := 1

	if input.Email != nil {
		setClauses = append(setClauses, fmt.Sprintf("email = $%d", argIdx))
		args = append(args, *input.Email)
		argIdx++
	}
	if input.PasswordHash != nil {
		setClauses = append(setClauses, fmt.Sprintf("password_hash = $%d", argIdx))
		args = append(args, *input.PasswordHash)
		argIdx++
	}
	if input.TOTPSecret != nil {
		setClauses = append(setClauses, fmt.Sprintf("totp_secret = $%d", argIdx))
		args = append(args, *input.TOTPSecret)
		argIdx++
	}
	if input.TOTPEnabled != nil {
		setClauses = append(setClauses, fmt.Sprintf("totp_enabled = $%d", argIdx))
		args = append(args, *input.TOTPEnabled)
		argIdx++
	}
	if input.Role != nil {
		setClauses = append(setClauses, fmt.Sprintf("role = $%d", argIdx))
		args = append(args, *input.Role)
		argIdx++
	}

	if len(setClauses) == 0 {
		return r.GetByID(ctx, id)
	}

	args = append(args, id)
	query := fmt.Sprintf("UPDATE admins SET %s WHERE id = $%d",
		joinClauses(setClauses), argIdx)

	result, err := r.db.Exec(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("update admin: %w", err)
	}
	if result.RowsAffected() == 0 {
		return nil, nil
	}
	return r.GetByID(ctx, id)
}

// UpdateLastLogin sets the last_login_at timestamp.
func (r *AdminRepo) UpdateLastLogin(ctx context.Context, id string) error {
	_, err := r.db.Exec(ctx,
		`UPDATE admins SET last_login_at = $1 WHERE id = $2`,
		time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("update last login: %w", err)
	}
	return nil
}

// Delete removes an admin.
func (r *AdminRepo) Delete(ctx context.Context, id string) (bool, error) {
	result, err := r.db.Exec(ctx, `DELETE FROM admins WHERE id = $1`, id)
	if err != nil {
		return false, fmt.Errorf("delete admin: %w", err)
	}
	return result.RowsAffected() > 0, nil
}
