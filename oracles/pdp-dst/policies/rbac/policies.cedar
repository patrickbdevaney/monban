@id("viewers-view")
permit(principal in Rbac::Role::"viewer", action == Rbac::Action::"view", resource)
when { principal.active };

@id("editors-edit-unclassified")
permit(principal in Rbac::Role::"editor", action in [Rbac::Action::"view", Rbac::Action::"edit"], resource)
when { principal.active && resource.classification != "secret" };

@id("admins-all")
permit(principal in Rbac::Role::"admin", action, resource)
when { principal.active };
