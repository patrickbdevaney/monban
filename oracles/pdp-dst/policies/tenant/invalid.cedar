// Must be refused at startup: comparing an entity to a string is a strict-mode type error.
@id("bad")
permit(principal, action, resource) when { principal.tenant == "acme" };
