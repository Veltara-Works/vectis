-- Phase 2A.4: Role-Based Admin Access
-- Adds domain_admin role scoping and normalizes role values.

-- 1. Normalize existing "superadmin" → "super_admin" per Spec B.
UPDATE admins SET role = 'super_admin' WHERE role = 'superadmin';

-- 2. Add CHECK constraint for valid roles.
ALTER TABLE admins
    ADD CONSTRAINT admins_role_check
    CHECK (role IN ('super_admin', 'admin', 'domain_admin'));

-- 3. Junction table: maps domain_admin users to their allowed domains.
CREATE TABLE admin_domains (
    admin_id    UUID NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    domain_id   UUID NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (admin_id, domain_id)
);

CREATE INDEX idx_admin_domains_admin ON admin_domains(admin_id);
CREATE INDEX idx_admin_domains_domain ON admin_domains(domain_id);

COMMENT ON TABLE admin_domains IS 'Maps domain_admin users to the domains they can manage. Ignored for admin/super_admin roles.';
