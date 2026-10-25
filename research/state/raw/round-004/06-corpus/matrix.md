| case | py-mcp-2.3.0/loopback-defau:l | py-mcp-2.3.0/loopback-defau:m | py-mcp-2.3.0/bind-0.0.0.0-d:l | py-mcp-2.3.0/bind-0.0.0.0-d:m | py-mcp-1.30.0/loopback-defau:l | ts-server-2.4.0+ex/legacy-transpo:l | ts-server-2.4.0/createMcpHandl:l | ts-server-2.4.0/createMcpHandl:m | ts-sdk-1.32.2+expr/default:l | rmcp-3.7.0/default-config:l | rmcp-3.7.0/default-config:m | rmcp-3.7.0/with_allowed_o:l | rmcp-3.7.0/with_allowed_o:m | agentgateway-1.6.0/docs-example-c:l | agentgateway-1.6.0/docs-example-c:m | agentgateway-1.6.0/jwt+aud+origin:l | agentgateway-1.6.0/jwt-audiences-:l | agentgateway-1.6.0/mock-upstream(:l | agentgateway-1.6.0/mcp-shorthand-:l | agentgateway-1.6.0/mcp-shorthand-:m | docker-mcp-gateway/token-auth(def:l | docker-mcp-gateway/--allow-unauth:l | agentgateway-1.6.0/mcp.dnsRebindi:l | agentgateway-1.6.0/mcp.dnsRebindi:m |
| host-allowlist-required | P | P | F | F | P | P | F | F | F | F | F | P | P | F | F | F | F |   | F | F | P | P | P | P |
| reject-text-plain-post | P | P | P | P | P | P | P | P | P | P | P | P | P | P | P | P | P |   | P | P | P | P | P | P |
| no-wildcard-cors | P | P | P | P | P | P | P | P | P | P | P | P | P | F | F | P | P |   | P | P | P | P | P | P |
| ws-origin-check | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - |   | - | - | - | - |   |   |
| host-allowlist-required;h2-authority | - |   | - |   | - | - | - |   | - | - |   | - |   | F |   | P | P |   | F |   |   |   | P |   |
| absent-origin-fail-closed | F | F | F | F | F | F | F | F | F | F | F | F | F | F | F | F | F |   | F | F | P | P | F | F |
| json-case-variant-reject | P | P | P | P | P | P | P | P | P | P | P | P | P | P | P | P | P |   | P | P |   |   |   |   |
| json-dup-nul-reject | F | F | F | F | F | F | F | F | F | P | P | P | P | P | P | P | P |   | P | P |   |   |   |   |
| json-bom-reject | P | F | P | F | F | F | F | F | F | P | P | P | P | P | P | P | P |   | P | P |   |   |   |   |
| policy-fail-closed | P | P | P | P | P | P | P | P | P | P | P | P | P | P | P | P | P |   | P | P |   |   |   |   |
| id-collision-two-clients | P | P | P | P | P | P | P | P | P | P | P | P | P | P | P | P | P |   | P | P | P | P |   |   |
| cache-bound | P | P | P | P | P | W | W | P | W | P | P | P | P | W | P | W | W |   | W | P |   |   |   |   |
| body-cap-413 | P | P | P | P | P | P | P | P | P | P | P | P | P | P | P | P | P |   | P | P | F | F |   |   |
| amplification-bound | P | P | P | P | P | P | P | P | P | P | P | P | P | P | P | P | P |   | P | P | P | P |   |   |
| unauth-listener-refused | F | F | F | F | F | F | F | F | F | F | F | F | F | F | F | P | P |   | F | F | P | F |   |   |
| N10-delete-session-legacy | P |   | P |   | P | - | - |   | W | P |   | P |   | P |   | P | P |   | P |   | P | P |   |   |
| token-wrong-audience-401 | - |   | - |   | - | - | - |   | - | - |   | - |   | - |   | P | F |   | - |   |   |   |   |   |
| session-principal-binding | - |   | - |   | - | - | - |   | - | - |   | - |   | - |   | F | F |   | - |   |   |   |   |   |
| session-route-pin | - |   | - |   | - | - | - |   | - | - |   | - |   | - |   | P | P |   | - |   |   |   |   |   |
| token-passthrough | - |   | - |   | - | - | - |   | - | - |   | - |   | - |   | - | - | F | - |   |   |   |   |   |
| redirect-strip-headers | - |   | - |   | - | - | - |   | - | - |   | - |   | - |   | - | - | P | - |   |   |   |   |   |
| toolname-collision | - |   | - |   | - | - | - |   | - | - |   | - |   | - |   | - | - |   | F |   |   |   |   |   |
| N01-header-mismatch-protocol-version |   | W |   | W |   |   |   | P |   |   | P |   | P |   | P |   |   |   |   | P |   |   |   | P |
| N02-missing-mcp-method-header |   | P |   | P |   |   |   | P |   |   | P |   | P |   | P |   |   |   |   | P |   |   |   |   |
| N03-mcp-name-mismatch |   | P |   | P |   |   |   | P |   |   | P |   | P |   | P |   |   |   |   | P |   |   |   |   |
| N04-unsupported-protocol-version |   | P |   | P |   |   |   | P |   |   | P |   | P |   | P |   |   |   |   | P |   |   |   |   |
| N05-no-session-id-issued |   | P |   | P |   |   |   | P |   |   | P |   | P |   | P |   |   |   |   | P |   |   |   |   |
| N06-removed-ping |   | P |   | P |   |   |   | P |   |   | P |   | P |   | P |   |   |   |   | P |   |   |   |   |
| N07-get-endpoint-removed |   | P |   | P |   |   |   | P |   |   | P |   | P |   | P |   |   |   |   | P |   |   |   |   |
| N08-initialize-under-modern |   | P |   | P |   |   |   | P |   |   | F |   | F |   | P |   |   |   |   | P |   |   |   |   |
| N09-simple-request-cannot-reach-modern |   | P |   | P |   |   |   | P |   |   | P |   | P |   | P |   |   |   |   | P |   |   |   | P |
| session-table-bound | W |   | W |   | W | P | P |   | W | W |   | W |   |   |   |   |   |   | W |   | P | P |   |   |
| verify-default-on |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   | P |   |   |   |
