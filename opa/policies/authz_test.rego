package agents.authz_test

import rego.v1

import data.agents.authz

a := "spiffe://example.org/agent-a"
b := "spiffe://example.org/agent-b"
rogue := "spiffe://example.org/agent-rogue"

# A request from agent-a acting for `user` through a token issued for `tool`.
for(user, tool) := {"caller": a, "target": b, "tool": tool, "user": user, "actor": a, "scope": tool}

test_maria_can_research if {
	authz.allow with input as for("maria", "research")
}

test_maria_cannot_delete if {
	d := authz.decision with input as for("maria", "delete_records")
	not d.allow
	d.reason == "user maria may not use \"delete_records\""
}

test_alex_can_delete if {
	authz.allow with input as for("alex", "delete_records")
}

test_no_token_denied if {
	d := authz.decision with input as {"caller": a, "target": b, "tool": "research", "user": "", "actor": "", "scope": ""}
	not d.allow
	startswith(d.reason, "a delegation token is required")
}

test_token_scope_must_match_tool if {
	d := authz.decision with input as object.union(for("alex", "research"), {"tool": "delete_records"})
	not d.allow
	d.reason == "token is scoped to \"research\", not \"delete_records\""
}

test_stolen_token_denied if {
	c := "spiffe://example.org/agent-c"
	d := authz.decision with input as object.union(for("maria", "research"), {"caller": c})
		with data.permissions as {c: {b: ["research"]}}
	not d.allow
	d.reason == sprintf("token was issued to %s but presented by %s", [a, c])
}

test_rogue_denied if {
	not authz.allow with input as object.union(for("maria", "research"), {"caller": rogue, "actor": rogue})
}

test_foreign_trust_domain_denied if {
	d := authz.decision with input as object.union(for("maria", "research"), {"caller": "spiffe://evil.com/agent-a"})
	d.reason == "caller is outside the trust domain"
}
