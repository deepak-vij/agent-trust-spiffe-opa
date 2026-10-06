package agents.authz_test

import rego.v1

import data.agents.authz

a := "spiffe://example.org/agent-a"
b := "spiffe://example.org/agent-b"
rogue := "spiffe://example.org/agent-rogue"

test_agent_a_can_research if {
	authz.allow with input as {"caller": a, "target": b, "tool": "research"}
}

test_agent_a_cannot_delete if {
	not authz.allow with input as {"caller": a, "target": b, "tool": "delete_records"}
}

test_rogue_denied if {
	not authz.allow with input as {"caller": rogue, "target": b, "tool": "research"}
}

test_foreign_trust_domain_denied if {
	d := authz.decision with input as {"caller": "spiffe://evil.com/agent-a", "target": b, "tool": "research"}
	d.allow == false
	d.reason == "caller is outside the trust domain"
}
