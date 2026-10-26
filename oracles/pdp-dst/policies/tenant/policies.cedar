@id("read-shared-or-own")
permit(principal, action == Saas::Action::"read", resource)
when { resource in principal.tenant && (resource.shared || resource.owner == principal) };

@id("owner-writes-with-mfa")
permit(principal, action == Saas::Action::"write", resource)
when { resource in principal.tenant && resource.owner == principal && context.mfa };

@id("tenant-admin")
permit(principal, action, resource)
when { resource in principal.tenant && principal.roles.contains("tenant-admin") && context.mfa };

@id("cross-tenant-guard")
forbid(principal, action, resource)
unless { principal.tenant == resource.tenant };

@id("stale-session")
forbid(principal, action == Saas::Action::"write", resource)
when { context.session_age_s > 3600 };
