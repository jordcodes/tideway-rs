# Deployment

Every app scaffolded with `tideway new` includes a production `Dockerfile` and `.dockerignore`.
This guide covers building that image and deploying it to [Fly.io](https://fly.io) or
[Railway](https://railway.com). Work through [Production Readiness](production_readiness.md)
before exposing the app to internet traffic.

`docker-compose.yml` (from `--with-docker`, `saas`, and `worker`) is for local PostgreSQL only;
it is not a production definition.

## The Production Image

The generated `Dockerfile` is a multi-stage build:

1. **Builder** ([cargo-chef](https://github.com/LukeMathWalker/cargo-chef) on Rust stable)
   compiles dependencies in a separate cached layer, then runs
   `cargo build --release --locked --bin <app>`. The first build compiles everything and takes
   several minutes; later builds that only change application code reuse the dependency layer
   and recompile just your crate, provided the host keeps Docker layer cache (Fly's remote
   builders and Railway both do). If the project has no `Cargo.lock` yet, one is generated
   first. Commit `Cargo.lock` so production builds use the dependency versions you tested and
   the dependency layer stays cached.
2. **Runtime** (`debian:bookworm-slim`) contains only CA certificates and the release binary,
   and runs as an unprivileged `app` user (UID 10001).

Runtime defaults:

| Variable | Default | Notes |
|----------|---------|-------|
| `TIDEWAY_HOST` | `0.0.0.0` | Listen on all interfaces inside the container. |
| `PORT` | `8000` | Tideway reads `TIDEWAY_PORT`, then `PORT`. Railway sets `PORT` for you. |
| `TIDEWAY_LOG_JSON` | `true` | Structured logs for the host's log pipeline. |
| `DATABASE_URL` | `sqlite:///app/data/<app>.db?mode=rwc` | Only set for SQLite apps (default `api` preset without `--with-docker`). |

Database-backed apps run pending SeaORM migrations at startup, so no separate release step is
required. With several replicas, migrations run on each boot; SeaORM records applied migrations,
but if you want only one process to migrate, run `tideway migrate` (or the `migration` binary)
as a release step and remove the startup call.

The `.env` file is excluded from the image. Supply secrets through the host's secret manager.

### Build and run locally

```bash
docker build -t my_app .
docker run --rm -p 8000:8000 \
  -e JWT_SECRET="$(openssl rand -base64 32)" \
  my_app
curl http://localhost:8000/health
```

Add `-e DATABASE_URL=postgres://...` for PostgreSQL apps. To reach the `docker compose` database
from the container on macOS/Windows, use `host.docker.internal` instead of `localhost`.

### Required configuration

Set whatever your scaffold's `.env.example` lists. Typical production values:

- `DATABASE_URL` - PostgreSQL connection string (PostgreSQL apps).
- `JWT_SECRET` - at least 32 random bytes (`openssl rand -base64 32`). Apps with `auth` refuse to
  start without it.
- `MFA_ENCRYPTION_KEY` - when `auth-mfa` is enabled; generate independently of `JWT_SECRET`.
- `TRUSTED_PROXY_IPS` / `TIDEWAY_RATE_LIMIT_TRUSTED_PROXIES` - set only to the host's proxy
  ranges; see [Production Readiness](production_readiness.md#network-boundary).
- `saas` preset: `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `STRIPE_PRICE_ID`, `APP_URL`, and
  email provider settings.

## Choosing a Database

The default `api` preset uses SQLite and is compiled with only the SQLite driver. SQLite works
for a single-instance deployment with a persistent volume, but PostgreSQL is recommended for
production on hosted platforms:

- Scaffold with PostgreSQL from the start: `tideway new my_app --with-docker`.
- Or switch an existing SQLite app: add `"sqlx-postgres"` to the `sea-orm` features in
  `Cargo.toml` and the `sea-orm-migration` features in `migration/Cargo.toml`, then set
  `DATABASE_URL` to a `postgres://` URL. Delete the `ENV DATABASE_URL=sqlite...` line from the
  `Dockerfile` so the host-provided value is used.

If you keep SQLite, mount a persistent volume at `/app/data` and run exactly one instance.
Without a volume the database is lost on every deploy.

## Fly.io

Prerequisites: the [`flyctl`](https://fly.io/docs/flyctl/install/) CLI and `fly auth login`.

1. Create the app without deploying. `fly launch` detects the `Dockerfile`:

   ```bash
   fly launch --no-deploy --name my-app
   ```

2. In the generated `fly.toml`, make sure the service targets the container port and uses the
   health endpoint:

   ```toml
   [http_service]
     internal_port = 8000
     force_https = true

   [[http_service.checks]]
     method = "GET"
     path = "/health"
     interval = "15s"
     timeout = "5s"
     grace_period = "30s"
   ```

3. Provision PostgreSQL and attach it. Attaching sets the `DATABASE_URL` secret:

   ```bash
   fly postgres create --name my-app-db
   fly postgres attach my-app-db --app my-app
   ```

   (Or point `DATABASE_URL` at any managed PostgreSQL with `fly secrets set`.)

4. Set the remaining secrets:

   ```bash
   fly secrets set JWT_SECRET="$(openssl rand -base64 32)"
   ```

5. Deploy and verify:

   ```bash
   fly deploy
   curl https://my-app.fly.dev/health
   ```

   Use `fly logs` if the machine fails its health check; startup panics such as
   `JWT_SECRET is not set` appear there.

**SQLite on Fly:** create a volume (`fly volumes create data --size 1`), add a
`[mounts]` section with `source = "data"` and `destination = "/app/data"`, and keep the app at a
single machine (`fly scale count 1`). Fly mounts volumes owned by `root`; if startup logs show
a permission error opening the database, remove the `USER app` line from the `Dockerfile` or use
PostgreSQL.

## Railway

Prerequisites: the [Railway CLI](https://docs.railway.com/guides/cli) and `railway login`, or a
GitHub repository connected through the Railway dashboard.

1. Create a project and service from the app directory:

   ```bash
   railway init
   ```

   Railway builds the root `Dockerfile` automatically.

2. Add PostgreSQL from the dashboard (**New → Database → PostgreSQL**), then reference its
   connection string in your app service's variables:

   ```text
   DATABASE_URL=${{Postgres.DATABASE_URL}}
   ```

3. Set the remaining variables in the dashboard or with the CLI:

   ```bash
   railway variables --set "JWT_SECRET=$(openssl rand -base64 32)"
   ```

   Do not set `PORT`; Railway injects it and Tideway listens on it.

4. Deploy:

   ```bash
   railway up
   ```

5. Generate a public domain under **Settings → Networking**, then set the healthcheck path to
   `/health` under **Settings → Deploy** so failed releases are not promoted.

**SQLite on Railway:** attach a volume to the service mounted at `/app/data` and keep one
replica. Railway volumes are mounted as `root`; set `RAILWAY_RUN_UID=0` on the service so the
non-root image can write to the volume.

## Other Hosts

The image is host-agnostic: any platform that runs a container, injects environment variables,
and routes HTTP to `$PORT` (default `8000`) will work. Point health checks at `/health`.
