# systemd example (bare Linux)

Reference units for **isolate** profile on a single host.

## Layout

| Unit | User | Purpose |
|---|---|---|
| `hyperbus-engine@acme.service` | `hb-engine-acme` | Engine + Postgres client |
| `support-bot.service` | `hb-agent-support` | Worker |
| `billing-bot.service` | `hb-agent-billing` | Worker |

Socket: `/run/hyperbus/acme.sock` (group `hb-agents`).

Optional Unix peer binding: [`peer-agents.yaml`](peer-agents.yaml) maps worker uid → `agent_id`
via `--peer-agent-map` on the engine (see `SO_PEERCRED` in design doc).

## Install

```bash
sudo cp hyperbus-engine@.service support-bot.service billing-bot.service /etc/systemd/system/
sudo cp peer-agents.yaml /etc/hyperbus/
sudo systemctl daemon-reload
sudo systemctl enable --now hyperbus-engine@acme.service support-bot.service billing-bot.service
```

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

See [`../../specs/001-runtime-isolation/design.md`](../../specs/001-runtime-isolation/design.md).
