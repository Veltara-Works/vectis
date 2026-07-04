package auth

// Role constants for admin access control.
const (
	RoleSuperAdmin  = "super_admin"
	RoleAdmin       = "admin"
	RoleDomainAdmin = "domain_admin"
)

// ValidRoles is the set of valid admin roles.
var ValidRoles = map[string]bool{
	RoleSuperAdmin:  true,
	RoleAdmin:       true,
	RoleDomainAdmin: true,
}

// IsValidRole returns true if the role string is a recognized role.
func IsValidRole(role string) bool {
	return ValidRoles[role]
}

// CanManageAdmins returns true if the role can create/delete other admins.
func CanManageAdmins(role string) bool {
	return role == RoleSuperAdmin
}

// CanAccessSystem returns true if the role can access config, orchestrator, and backup endpoints.
func CanAccessSystem(role string) bool {
	return role == RoleSuperAdmin
}

// CanAccessAllDomains returns true if the role has unrestricted domain access.
func CanAccessAllDomains(role string) bool {
	return role == RoleSuperAdmin || role == RoleAdmin
}
