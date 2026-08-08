# systemd example (bare Linux)

Reference units for **isolate** profile on a single host.

## Layout

| Unit | User | Purpose |
|---|---|---|
| `hyperbus-engine@acme.service` | `hb-engine-acme` | Engine + Postgres client |
| `support-bot.service` | `hb-agent-support` | Worker |
| `billing-bot.service` | `hb-agent-billing` | Worker |

Socket: `/run/hyperbus/acme.sock` (group `hb-agents`).

## Environment (support-bot.service excerpt)

```ini
Environment=HB_TENANT_ID=acme
Environment=HB_AGENT_ID=support-bot
Environment=HB_DEFAULT_REGION=support
Environment=HB_ISOLATION_PROFILE=isolate
Environment=HYPERBUS_SOCKET=/run/hyperbus/acme.sock
ExecStart=/opt/hyperbus/venv/bin/hyperbus-worker python /opt/agents/support/graph.py
```

Engine holds `DATABASE_URL`; workers do not.

Full unit files to be added when RPC daemon lands — track
[`specs/001-runtime-isolation/spec.md`](../../specs/001-runtime-isolation/spec.md).
