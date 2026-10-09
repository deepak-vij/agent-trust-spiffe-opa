# Delegation policy, queried by the token service.
#
# Input: may `actor` obtain a token to act for `user`, toward `audience`,
# for the tool in `scope`?
package agents.delegation

import rego.v1

default allow := false

allow if {
	input.scope != ""
	input.audience in data.delegation[input.actor]
}

reason := "granted" if {
	allow
} else := "a delegation token must be scoped to one tool" if {
	input.scope == ""
} else := sprintf("%s may not act on behalf of users toward %s", [input.actor, input.audience])

decision := {"allow": allow, "reason": reason}
