# Agent-to-agent authorization policy, with delegation.
#
# Input (sent by agent-b on every request):
#   caller: SPIFFE ID of the calling agent, verified by mTLS
#   target: SPIFFE ID of the agent being called
#   tool:   the tool / capability being invoked
#   user:   the user the caller acts for, from a verified delegation token ("" if none)
#   actor:  the agent the delegation token was issued to (its "act" claim)
#   scope:  the tool the delegation token was issued for
package agents.authz

import rego.v1

trust_domain := "spiffe://example.org/"

default allow := false

# Allow only when the agent AND the user it acts for may use the tool, and the
# token was issued to this very agent, for this very tool.
allow if {
	startswith(input.caller, trust_domain)
	input.tool in data.permissions[input.caller][input.target]
	input.actor == input.caller
	input.scope == input.tool
	input.tool in data.user_permissions[input.user]
}

reason := "granted: agent and user are both permitted" if {
	allow
} else := "caller is outside the trust domain" if {
	not startswith(input.caller, trust_domain)
} else := sprintf("%s has no permissions on %s", [input.caller, input.target]) if {
	not data.permissions[input.caller][input.target]
} else := sprintf("tool %q is not granted to %s", [input.tool, input.caller]) if {
	not input.tool in data.permissions[input.caller][input.target]
} else := "a delegation token is required: agents may only act on behalf of a user" if {
	input.user == ""
} else := sprintf("token was issued to %s but presented by %s", [input.actor, input.caller]) if {
	input.actor != input.caller
} else := sprintf("token is scoped to %q, not %q", [input.scope, input.tool]) if {
	input.scope != input.tool
} else := sprintf("user %s may not use %q", [input.user, input.tool])

# Single object the agents query: {"allow": bool, "reason": string}
decision := {"allow": allow, "reason": reason}
