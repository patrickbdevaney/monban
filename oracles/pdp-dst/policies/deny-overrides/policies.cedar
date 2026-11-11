@id("owner-may")
permit(principal, action, resource) when { resource.owner == principal };

@id("frozen")
forbid(principal, action in [Bank::Action::"withdraw", Bank::Action::"transfer"], resource)
when { resource.frozen };

@id("blocked")
forbid(principal, action, resource) when { principal.blocked };

@id("over-limit")
forbid(principal, action in [Bank::Action::"withdraw", Bank::Action::"transfer"], resource)
when { context.amount > resource.limit };

@id("sanctioned-country")
forbid(principal, action == Bank::Action::"transfer", resource)
when { ["XX", "YY"].contains(context.country) };

@id("fraud-flag")
forbid(principal, action, resource) when { context.flags.contains("fraud-suspected") };

// Risk-weighted exposure. `amount * risk` can overflow: Cedar then skips this forbid (and would Allow);
// Monban treats any evaluation error as Error, hence Deny.
@id("risk-exposure")
forbid(principal, action == Bank::Action::"transfer", resource)
when { context.amount * principal.risk > 1000000 };
