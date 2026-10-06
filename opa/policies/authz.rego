# Agent-to-agent authorization policy.
#
# Input (sent by the callee on every request):
#   caller: SPIFFE ID of the calling agent, verified by mTLS
#   target: SPIFFE ID of the agent being called
#   tool:   the tool / capability being invoked
package agents.authz

import rego.v1

trust_domain := "spiffe://example.org/"

default allow := false

# Allow when the caller is in our trust domain and has been granted
# this tool on this target in data.json.
allow if {
	startswith(input.caller, trust_domain)
	input.tool in data.permissions[input.caller][input.target]
}

default reason := "no permission grants this call"

reason := "granted by permissions" if allow

reason := "caller is outside the trust domain" if {
	not startswith(input.caller, trust_domain)
}

reason := sprintf("%s has no permissions on %s", [input.caller, input.target]) if {
	startswith(input.caller, trust_domain)
	not data.permissions[input.caller][input.target]
}

reason := sprintf("tool %q is not granted to %s", [input.tool, input.caller]) if {
	data.permissions[input.caller][input.target]
	not input.tool in data.permissions[input.caller][input.target]
}

# Single object the agents query: {"allow": bool, "reason": string}
decision := {"allow": allow, "reason": reason}
