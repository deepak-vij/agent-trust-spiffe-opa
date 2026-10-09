# Agent-to-Agent trust with SPIFFE/SPIRE + OPA (PoC)

```
              SPIRE Server (CA, trust domain example.org)
                     │ join_token node attestation
              SPIRE Agent ── Workload API socket (unix attestor: uid)
          ┌──────────┬────────┴──────┬─────────────────┐
     agent-a (1001)  agent-b (1002)  agent-rogue (1003)  token-service (1004)
     orchestrator ──mTLS──▶ research ◀──mTLS── agent-rogue
          │  "act for maria,          │
          │   research only"          ▼
          └──▶ token-service         OPA  (opa/policies/*.rego + data.json)
               (RFC 8693 exchange)    ▲
                     └────────────────┘ "may agent-a act for users?"
```

Three questions, three layers:

| Layer | Question | Where |
|---|---|---|
| **Authentication** | Which agent is calling? | mTLS with SPIFFE SVIDs from SPIRE |
| **Delegation** | On whose behalf? | A short-lived token from the token service: user + acting agent + one tool |
| **Authorization** | May they do this? | OPA, per request: the agent **and** the user must both be allowed |

## Delegation, not impersonation
Agents never hold a user's credentials. Instead:

1. The user signs in. Here the token service's `/login` stands in for an identity provider such as Okta or Entra ID.
2. agent-a, authenticated by its own SPIFFE ID over mTLS, trades the user's token at `/token` (OAuth 2.0 Token Exchange, [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693)) for a 5-minute token: `sub` = the user, `act.sub` = agent-a, `aud` = agent-b, `scope` = one tool. The token service asks OPA (`agents.delegation`) whether agent-a may act for users at all.
3. agent-a calls agent-b with that token. agent-b checks its signature against the token service's keys, fetched over mTLS, and asks OPA (`agents.authz`).
4. OPA allows the call only if the agent may use the tool, the user may use the tool, the token was issued to this very agent (not stolen) and for this very tool.

## What the demo shows (`opa/policies/data.json`)

| Call | Result | Why |
|---|---|---|
| agent-a for **maria** → research | ✅ 200 | agent and user both permitted |
| agent-a for **maria** → delete_records | ❌ 403 | `user maria may not use "delete_records"` (the agent could) |
| agent-a for **alex** → delete_records | ✅ 200 | alex is an admin |
| agent-a with **no user** → research | ❌ 403 | `a delegation token is required` |
| agent-a, maria's token **edited to say alex** | ❌ 401 | bad signature |
| **agent-rogue** for maria → research | ❌ refused by token service | rogue may not act on behalf of users |

The effective permission is the **intersection** of what the agent may do and what the user may do.

## Run
```bash
./run.sh
docker compose logs -f agent-a agent-b agent-rogue token-service
./teardown.sh
```

## Change policy live
OPA runs with `--watch`, so edits apply within seconds and nothing needs restarting. For example, add
`"delete_records"` to maria's list under `user_permissions` in `opa/policies/data.json`, and watch
agent-a's `DENIED delete_records for maria` turn into `OK`.

Test the policies:
```bash
docker run --rm -v "$PWD/opa/policies:/p:ro" openpolicyagent/opa:1.9.0-static test -v /p
```

## Design notes
- **Fail closed**: if OPA is unreachable, agent-b and the token service refuse.
- **Identity comes from mTLS, not the request**: `caller` (agent-b) and the token's `act` claim
  (token service) are both read from the verified peer certificate, so an agent can't claim to
  be someone else or obtain a token in another agent's name.
- **Tokens are narrow and short-lived**: one target, one tool, 5 minutes.
- **No shared secrets**: the token service generates its signing key at startup and publishes
  only the public key; agent-b fetches it over mTLS.
- **PoC shortcuts**: `/login` issues tokens for demo users without a password; OPA is reached over
  plain HTTP on the Docker network. In production, use a real identity provider, run OPA as a
  localhost sidecar (or embed it as a Go library), and load policy as signed bundles.

## Files
- `spire/server/server.conf`, `spire/agent/agent.conf`: SPIRE config
- `agent/main.go`: entry point and agent-b's tool server; `client.go`: calling agents;
  `tokenservice.go`: token service; `tokens.go`: JWT signing and verification (`go-spiffe/v2`, `go-jose/v4`)
- `opa/policies/authz.rego`: call authorization; `delegation.rego`: who may act for users;
  `data.json`: agent and user permissions; `*_test.rego`: unit tests
- `run.sh` / `teardown.sh`: bootstrap and cleanup

## License
Apache License 2.0. See [LICENSE](LICENSE).
