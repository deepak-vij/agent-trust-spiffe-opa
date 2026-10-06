# Agent-to-Agent trust with SPIFFE/SPIRE + OPA (PoC)

```
              SPIRE Server (CA, trust domain example.org)
                     │ join_token node attestation
              SPIRE Agent ── Workload API socket (unix attestor: uid)
          ┌──────────┼───────────────┐
     agent-a (1001)  agent-b (1002)  agent-rogue (1003)
     orchestrator ──mTLS──▶ research ◀──mTLS── agent-rogue
                              │
                              ▼  "may <caller> use <tool> on <me>?"
                             OPA  (opa/policies/*.rego + data.json)
```

Two layers, two questions:

| Layer | Question | Where |
|---|---|---|
| **Authentication** | Who is calling? | mTLS with SPIFFE SVIDs. agent-b accepts any member of `example.org` (`agent/main.go`, `AuthorizeMemberOf`). |
| **Authorization**  | May they do this? | OPA, per request: `caller` + `target` + `tool` → allow/deny + reason. |

## Who can do what (`opa/policies/data.json`)

| Caller | research | summarize | delete_records |
|---|---|---|---|
| agent-a     | ✅ | ✅ | ❌ 403 |
| agent-rogue | ❌ 403 | — | — |
| other trust domain | rejected | | |

## Run
```bash
./run.sh
docker compose logs -f agent-a agent-b agent-rogue
./teardown.sh
```

## Change policy live
OPA runs with `--watch`, so edits apply within seconds and nothing needs restarting. For example, add
`"delete_records"` to agent-a's list in `opa/policies/data.json` and watch agent-a's
`DENIED delete_records` turn into `OK`.

Test the policy:
```bash
docker run --rm -v "$PWD/opa/policies:/p:ro" openpolicyagent/opa:1.9.0-static test -v /p
```

## Design notes
- **Fail closed**: if OPA is unreachable, agent-b returns 503 and does nothing.
- **Identity comes from mTLS, not the request body**: the `caller` sent to OPA is read
  from the verified peer certificate, so an agent can't claim to be someone else.
- **PoC shortcuts**: OPA is reached over plain HTTP on the Docker network. In production,
  run OPA as a localhost sidecar (or embed it as a Go library) and load policy as signed bundles.

## Files
- `spire/server/server.conf`, `spire/agent/agent.conf`: SPIRE config
- `opa/policies/authz.rego`: policy; `data.json`: permissions; `authz_test.rego`: unit tests
- `agent/main.go`: Go agent (`MODE=server|client`) using `go-spiffe/v2`
- `run.sh` / `teardown.sh`: bootstrap and cleanup

## License
Apache License 2.0. See [LICENSE](LICENSE).
