// Oracle-subject policy for oracles/mcp-corpus: any authenticated subject may use the served MCP methods on the
// configured routes; one named subject is always forbidden (forbid overrides permit).
permit (
  principal,
  action == Mcp::Action::"invoke",
  resource
)
when {
  ["initialize", "notifications/initialized", "notifications/cancelled", "ping", "tools/list", "tools/call",
   "resources/list", "prompts/list"].contains(context.method)
};

forbid (principal == Mcp::User::"mallory", action, resource);
