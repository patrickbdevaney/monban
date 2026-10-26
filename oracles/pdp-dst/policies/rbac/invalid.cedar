// Must be refused at startup: `salary` is not a User attribute (strict validation error).
@id("bad")
permit(principal, action == Rbac::Action::"view", resource) when { principal.salary > 3 };
