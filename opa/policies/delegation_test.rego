package agents.delegation_test

import rego.v1

import data.agents.delegation

a := "spiffe://example.org/agent-a"
b := "spiffe://example.org/agent-b"

test_agent_a_may_act_toward_agent_b if {
	delegation.allow with input as {"actor": a, "user": "maria", "audience": b, "scope": "research"}
}

test_rogue_may_not_act_for_users if {
	d := delegation.decision with input as {"actor": "spiffe://example.org/agent-rogue", "user": "maria", "audience": b, "scope": "research"}
	not d.allow
}

test_agent_a_limited_to_listed_targets if {
	not delegation.allow with input as {"actor": a, "user": "maria", "audience": "spiffe://example.org/payments", "scope": "research"}
}

test_unscoped_token_refused if {
	d := delegation.decision with input as {"actor": a, "user": "maria", "audience": b, "scope": ""}
	d.reason == "a delegation token must be scoped to one tool"
}
