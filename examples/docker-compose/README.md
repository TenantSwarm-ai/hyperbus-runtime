# Docker Compose example

Demonstrates **isolate** profile: `support-bot` and `billing-bot` are separate
containers; only `hyperbus-engine` reaches Postgres.

```bash
cd examples/docker-compose
docker compose up --build   # fails until RPC engine is implemented
```

Grant file: [`acme-grants.yaml`](acme-grants.yaml).

Workers set `HYPERBUS_ENGINE_URL` (no `DATABASE_URL`). Engine mounts grants and
holds `DATABASE_URL`.

See [`../../specs/001-runtime-isolation/design.md`](../../specs/001-runtime-isolation/design.md).
