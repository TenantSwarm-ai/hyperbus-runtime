# Feature Spec: Verified Agent Identity Binding

**Status:** Draft  
**Repository:** `hyperbus-runtime`  
**Baseline:** `main` @ `fccb433`  
**Depends on:** [`001-runtime-isolation`](../001-runtime-isolation/spec.md) (AC-7.1, AC-7.2), hyperbus-core `specs/009-durable-grant-events` (durable audit), hyperbus-core `specs/012-runtime-isolation`  
**Constitution:** II.4, II.4a, II.7, III, VII.1, VII.3

## 1. Problem Statement

The engine sidecar decides what an agent may do from `agent_id`. Today that value is **declared by the caller**, not verified.

- **HTTP path.** One shared `HYPERBUS_RPC_TOKEN` authenticates the transport. The request body's `agent_id` is then trusted (`rpc_dispatch._validate_request`). Any process holding the token can act as any agent.
- **Unix socket path.** `SO_PEERCRED` binds a caller to an agent only when `--peer-agent-map` is configured. Without it, `peer_cred.resolve_agent_id` returns the declared id unchanged.
- **Grant state.** On `main`, `engine_daemon.create_engine` builds an `InMemoryAuditStore` on every start and loads grants only from YAML. The admin API that mutates grants at runtime (001 AC-7.2) is uncommitted in the primary checkout, and its changes live only in memory. A restart loses them and re-applies whatever the YAML still lists.

Operators need to block and allow connectivity per identity, the same way grants work today. That requires three things: the engine verifies a credential, the verified identity maps to an `agent_id` through a map that operators can change, and the decision survives a restart.

## 2. Decisions (recorded)

- **D1 — Four identity sources.** Microsoft Entra Agent ID, AWS Bedrock AgentCore workload identity, SPIFFE/SPIRE, and generic OIDC workload tokens. All four reduce to two verification mechanisms (section 4).
- **D2 — Role granularity.** Many identities may map to one `agent_id`. Replicas of one role share one `agent_id` and one grant set. One identity still maps to exactly one `agent_id`.
- **D3 — Mapping decisions live in `hyperbus-cloud`.** Automatic rules and manual dual-controlled approval both happen there. The engine enforces only the map it is given and does not call the cloud (VII.3).

## 3. Goals and Non-Goals

**Goals**

- **G1:** The engine authenticates each caller from a credential it verifies, never from a body field.
- **G2:** Removing an identity from the map denies its next request without restart, even while its credential is still valid.
- **G3:** Identity denials and map changes are auditable. No credential material reaches logs or audit.
- **G4:** Identity blocks and grant revocations survive an engine restart.

**Non-Goals**

- Discovering identities in source systems or calling their APIs (Entra, AgentCore, SPIRE). That is cloud inventory work in a separate `hyperbus-cloud` spec. The runtime verifies credentials and reads a local map.
- Proving that the running code is the code that was deployed. A verified credential proves the caller holds a credential the source issued. This is not attestation (II.4).
- Per-replica isolation. Under D2 a compromised replica's credential acts for the whole role.
- Revoking a credential before it expires. No CRL or OCSP. Mitigations are short credential lifetime and map removal (AC-3.6).
- Human or operator authentication. That is cloud spec 012.
- Any call to a HyperBus-operated service (VII.3). The map, JWKS or trust bundle, and audit sink are all customer-configured.

## 4. Trust Model

Each source is expected to issue either a JWT or an X.509 SVID (see A-1), so two mechanisms would cover all four.

| Source | Credential the engine verifies | Mechanism | Identity used for mapping |
|---|---|---|---|
| Microsoft Entra Agent ID | Entra-issued access token | JWT | Claim named in config (candidate: `oid`) |
| AWS Bedrock AgentCore | Workload access token | JWT | Claim named in config (to confirm) |
| SPIFFE / SPIRE | X.509-SVID (mTLS) or JWT-SVID | X.509 or JWT | SPIFFE ID (`spiffe://...`) |
| Generic OIDC workload | Signed JWT | JWT | `sub` |

**Assumption A-1.** The Entra and AgentCore rows describe token types and claim names as understood at drafting. They are **not verified** against vendor documentation in this spec. Each row must be confirmed before that source is implemented (Q6).

## 5. Identity Map

A local YAML file, loaded at startup and re-read on `SIGHUP`. The engine is the only consumer. The cloud generates it.

```yaml
tenant_id: acme
change_ref: CHG-1042            # optional; copied into audit, not enforced here
agents:
  support-bot:
    unix_uids: [1103]
    identities:
      - type: spiffe
        match: "spiffe://acme.example/ns/prod/sa/support-bot-*"   # role: many replicas
      - type: jwt
        issuer: "https://login.example.com/acme/v2.0"
        claim: oid
        match: "6d1f0c2e-8a7b-4f3d-9e21-0b5c7a9d4e10"
  billing-bot:
    unix_uids: [1104]
    identities:
      - type: spiffe
        match: "spiffe://acme.example/ns/prod/sa/billing-bot-*"
  retired-bot:
    unix_uids: []
    identities: []              # blocked: loads, denies everything
```

Map rules are in AC-3.x below.

## 6. Modes

`--identity-mode {declared,verified}` (env `HYPERBUS_IDENTITY_MODE`):

- **`declared`** — current behavior. `agent_id` is caller-declared. Documented as **not an identity boundary**. Default in 0.x (Q1).
- **`verified`** — every transport requires a verified identity. This spec defines it.

## 7. User Stories and Acceptance Criteria

### US-1: Verified identity on HTTP

- **AC-1.1:** In `verified` mode, an HTTP RPC without a credential the engine accepts gets `401` before the body is parsed or dispatched.
- **AC-1.2:** The credential maps to one `agent_id`. If the body carries an `agent_id` that differs, respond `403` and audit `identity.denied` with reason `body_agent_mismatch`. The body never selects the identity.
- **AC-1.3:** `HYPERBUS_RPC_TOKEN` alone is not sufficient in `verified` mode. It may stay as a transport gate. It never authenticates an agent.
- **AC-1.4:** In `verified` mode, HTTP requires TLS (001 AC-7.1). A bearer JWT over plaintext HTTP is refused at startup.
- **AC-1.5:** `client.py` presents its credential (mTLS certificate or bearer JWT). The body `agent_id` is still sent for compatibility but is only checked against the verified identity (AC-1.2).

### US-2: Verified identity on the Unix socket

- **AC-2.1:** In `verified` mode, every Unix connection must resolve to an agent through `SO_PEERCRED` uid, using the map's `unix_uids`. Missing peer credentials refuse the connection, as `resolve_agent_id` already does when a map is set.
- **AC-2.2:** The declared `agent_id` must equal the resolved one. A mismatch is denied (the existing check, now mandatory).
- **AC-2.3:** In `verified` mode, `unix_uids` in the identity map replace `--peer-agent-map`. One file is the source of truth. `declared` mode keeps the old peer-map behavior.

### US-3: Identity map

- **AC-3.1:** Each identity carries an explicit `type` (`spiffe` or `jwt`). A `match` value may end in a single trailing `*`. A bare `*` or an empty `match` is rejected at load.
- **AC-3.2:** A single identity matching two agents fails the load. There is no silent winner.
- **AC-3.3:** Many identities may map to one `agent_id`. The load audit (AC-5.2) reports the identity count per agent.
- **AC-3.4:** An agent with no identities and no `unix_uids` loads as **blocked**. The engine logs that at load.
- **AC-3.5:** The map's `tenant_id` must equal the engine's tenant. A mismatch refuses startup, as grants do today.
- **AC-3.6:** The map is consulted on **every request**, not cached per connection. Removing an identity denies its next request without restart, including on keep-alive HTTP and open Unix connections.
- **AC-3.7:** `SIGHUP` re-reads and atomically swaps the map. If validation fails, the engine denies **all identity-bound requests** until a valid map loads, and audits `identity.map_rejected` (Q5).

### US-4: Credential verification

- **AC-4.1 (JWT):** Verify the signature against the configured JWKS or static keys. Check `iss`, `aud`, `exp`, and `nbf`, with clock skew of at most 60 s (Q4). Allowlist `RS256` and `ES256`. Reject `none` and HMAC algorithms.
- **AC-4.2 (JWKS freshness):** Keys refresh in the background. The request path performs no network I/O. Keys past their maximum age with a failed refresh deny with reason `jwks_stale`.
- **AC-4.3 (X.509 / SPIFFE):** The client chain verifies against the configured trust bundle. The certificate must be within its validity period. Exactly one URI SAN with the `spiffe://` scheme must be present, and its trust domain must equal the configured one.
- **AC-4.4:** Unknown `kid`, bad signature, expired, and wrong audience each deny with a distinct reason code.
- **AC-4.5 (revocation honesty):** No CRL or OCSP is added. Docs state that a credential stays usable until it expires. The engine's revocation lever is map removal (AC-3.6).

### US-5: Audit and log hygiene

- **AC-5.1:** Each denial emits `identity.denied` with transport, reason code, and the presented identity (SPIFFE ID, or JWT issuer and subject). Never the token or key material.
- **AC-5.2:** Each map load or reload emits `identity.map_loaded` with the map hash, `change_ref` if present, and identity counts per agent.
- **AC-5.3:** Successful verifications are not audited per request.
- **AC-5.4:** A red-team test scans logs and audit detail and fails if a token string, private key, or certificate PEM appears.
- **AC-5.5:** Identity audit goes to the same sink the engine uses for grants (in-memory or Postgres).

### US-6: Durable grant and block state

- **AC-6.1:** Grant mutations and revocations are written to durable audit. On boot the engine rebuilds its registry from the durable audit log. YAML supplies only grants that the audit log has no decision for.
- **AC-6.2:** A grant revoked in audit stays revoked after restart, even if the YAML still lists it.
- **AC-6.3:** `verified` mode refuses to start with `InMemoryAuditStore`. A dev-only `--allow-volatile-grants` flag overrides this and logs a warning.
- **AC-6.4 (core dependency):** Rebuilding from the whole tenant's audit log needs a tenant-wide replay API in `hyperbus-core`. Core has per-agent `grants_at` today. The runtime does not reimplement replay (VII.1). The replay API needs its own core spec.

### US-7: Boundary and self-hosting

- **AC-7.1:** `verified` mode makes zero calls to HyperBus-operated services. The map, JWKS or trust bundle URLs, and audit sink are all customer-configured.
- **AC-7.2:** A CI check fails if `hyperbus-runtime` imports `hyperbus_cloud` or any hosted package.
- **AC-7.3:** The map is the only contract between cloud inventory and the engine. The cloud never writes engine state directly.
- **AC-7.4:** Identity-to-`agent_id` mapping lives in the runtime (Q2). Maintainer sign-off under VII.1 is pending.

### US-8: Measured overhead

- **AC-8.1:** Verification overhead is measured with the 001 IPC benchmark, comparing `verified` against `declared` on the same host and transport. Any published number names that baseline (II.4a).

## 8. Dependencies

- **001 AC-7.1 (TLS / mTLS).** `src/hyperbus_runtime/tls.py` exists in the primary checkout as uncommitted work and is not on `main`. `verified` HTTP (AC-1.4) depends on it landing first.
- **001 AC-7.2 (admin port).** Admin mutations become durable through US-6.
- **001 AC-7.3 (IPC benchmark).** `src/hyperbus_runtime/bench_ipc.py` is also uncommitted in the primary checkout. AC-8.1 uses it.
- **hyperbus-core.** Durable audit (`PostgresAuditStore`, spec 009). A tenant-wide grant replay API (AC-6.4) is new and needs a core spec.
- **Uncommitted primary work.** `rpc_server.py`, `client.py`, `engine_daemon.py`, and `worker.py` have uncommitted changes in the primary checkout. Implementation rebases onto them when they merge.

## 9. Verification

Adversarial tests, in `tests/test_identity_verified.py` (new) unless noted:

| Test | Asserts |
|---|---|
| Valid credential for `support-bot`, body `agent_id=billing-bot` | `403`, `identity.denied` |
| Shared `HYPERBUS_RPC_TOKEN` only, `verified` mode | `401` before dispatch |
| Valid credential for an unmapped identity | Denied, reason `unmapped` |
| Two agents claim the same SPIFFE ID in the map | Load fails (AC-3.2) |
| `match: "*"` or empty `match` | Load fails (AC-3.1) |
| Remove identity from map (`SIGHUP`) while its token is still valid | Next request denied (AC-3.6) |
| JWT with `alg=none`, `alg=HS256` using the public key as secret, expired, wrong `aud` | Each denied with its reason (AC-4.1, AC-4.4) |
| JWKS refresh failing past max age | `jwks_stale`; no network call on request path (AC-4.2) |
| X.509: expired cert, missing URI SAN, two `spiffe://` SANs, wrong trust domain | Each denied (AC-4.3) |
| Map reload fails validation | All identity-bound requests denied (AC-3.7) |
| Grant revoked, restart, YAML still lists it | Still denied (AC-6.2) |
| `verified` with `InMemoryAuditStore` | Refuses to start (AC-6.3) |
| `verified` over plaintext HTTP with a bearer JWT | Refuses to start (AC-1.4) |
| Log and audit scan for token, key, PEM | None present (AC-5.4) |
| Unix uid unmapped; uid mapped to A declares B | Denied (AC-2.1, AC-2.2) |

**Existing tests that remain valid:** `tests/test_peer_cred.py` (`resolve_agent_id` cases), `tests/test_penetration.py::TestIdentitySpoofing`, and `tests/test_rpc_server.py::test_http_handler_rejects_missing_token`. Extend them to `verified` mode rather than duplicating them.

No test in `verified` mode may authenticate an agent from the request body.

## 10. Decisions and Open Questions

- **Q1 — Default mode (decided).** `declared` stays the default in 0.x for compatibility (Article V). The README marks it "not an identity boundary". The reference deployments (`examples/docker-compose`, `examples/systemd`) switch to `verified`.
- **Q2 — Owner of identity-to-`agent_id` mapping (decided: runtime).** The logic stays in `hyperbus-runtime`, following the precedent in `peer_cred.py`. Maintainer sign-off under VII.1 is still required before merge.
- **Q3 — Delivering map updates to self-hosted engines.** The engine must not call the cloud (VII.3). **Recommendation:** the operator distributes the file (GitOps or ConfigMap), and the engine reloads on `SIGHUP`. The cloud-hosted delivery path belongs in the cloud spec.
- **Q4 — Clock skew.** 60 s proposed.
- **Q5 — Failed-reload policy (decided: deny-all).** A failed reload denies all identity-bound requests until a valid map loads (AC-3.7). This matches the cloud rule that stale policy denies at runtime.
- **Q6 — Claim names and token types** for Entra and AgentCore (A-1). Confirm against vendor documentation before implementing those sources.
