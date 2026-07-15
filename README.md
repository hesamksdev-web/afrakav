# Afranet — Afrashodan

A Shodan-style **multi-tenant exposure-intelligence platform** for Afranet. An admin
uploads Tenable **Nessus** (`.nessus`) scans and assigns each to a customer; customers
log in and see **only their own** hosts — searching by IP, hostname, or CVE and
reviewing every open port, service banner, and vulnerability finding.

```
┌─────────────────┐   REST + JWT   ┌──────────────────────────┐   SQL   ┌────────────┐
│  React + Vite   │ ─────────────▶ │   Go backend (net/http)  │ ──────▶ │ PostgreSQL │
│  login / admin  │ ◀───────────── │  Nessus parser · auth ·  │ ◀────── │  (volume)  │
│  / customer UI  │                │  per-tenant scoping      │         └────────────┘
└─────────────────┘                └──────────────────────────┘
```

Every data request is scoped server-side by the authenticated user, so a customer can
**never** read another tenant's IPs — even by tampering with query parameters.

## Roles

- **Admin** — creates customer accounts (username + password), uploads `.nessus` files
  and assigns each to a customer. Sees the admin panel, not the search UI.
- **Customer** — logs in with admin-issued credentials, sees a Shodan-style dashboard
  scoped to their own scans. No upload button.

## Run with Docker (recommended)

Brings up Postgres, the Go backend, and the nginx-served UI. nginx proxies `/api` to
the backend (single origin, no CORS). Postgres data persists in a named volume.

```bash
docker compose up -d --build
```

- UI:          http://localhost:8081
- Backend API: http://localhost:8080 (also at http://localhost:8081/api)

**Default seeded accounts** (set in `docker-compose.yml` — change for production):

| Role     | Username | Password     |
|----------|----------|--------------|
| Admin    | `admin`  | `admin12345` |
| Customer | `demo`   | `demo12345`  | ← seeded with the sample scan

```bash
docker compose ps        # status / health
docker compose logs -f   # tail logs
docker compose down      # stop (keeps data volume)
docker compose down -v   # stop AND wipe the database
```

## Run locally (without Docker)

Needs a running Postgres. Point the backend at it via `DATABASE_URL`:

```bash
cd backend
export DATABASE_URL="postgres://afrashodan:afrashodan@localhost:5432/afrashodan?sslmode=disable"
export JWT_SECRET="dev-secret" ADMIN_USER=admin ADMIN_PASSWORD=admin12345
export DEMO_USER=demo DEMO_PASSWORD=demo12345 AFRASHODAN_SEED=data/sample.nessus
go run .
```

```bash
pnpm install
VITE_API_URL=http://localhost:8080 pnpm dev   # Vite dev server on :5173
```

## Backend API

Public:

| Method | Path            | Description                                  |
|--------|-----------------|----------------------------------------------|
| POST   | `/api/login`    | `{username,password}` → `{token, user}`      |
| GET    | `/api/health`   | liveness probe                               |

Authenticated (`Authorization: Bearer <token>`):

| Method | Path               | Description                                             |
|--------|--------------------|---------------------------------------------------------|
| GET    | `/api/me`          | current user                                            |
| GET    | `/api/hosts`       | caller's hosts (admin may pass `?customerId=`)          |
| GET    | `/api/hosts/{ip}`  | one host by IP, scoped                                  |
| GET    | `/api/search?q=`   | Shodan-style query, scoped                              |
| GET    | `/api/stats`       | dashboard aggregates, scoped                            |
| GET    | `/api/scans`       | upload history, scoped                                  |

Admin only:

| Method | Path                     | Description                                       |
|--------|--------------------------|---------------------------------------------------|
| GET    | `/api/admin/customers`   | list customers with host/scan counts              |
| POST   | `/api/admin/customers`   | `{username,password,displayName}`                 |
| POST   | `/api/admin/upload`      | multipart: `file=.nessus`, `customerId=<id>`      |

**Search grammar:** `port:445`, `tag:rdp`, `vuln:CVE-2021-44228`, `cve:…`,
`product:jenkins`, `os:windows`, or a bare term matching IP / hostname / domain / OS /
org / port / service / CVE / plugin name.

### Environment variables (backend)

| Var               | Default                          | Purpose                                    |
|-------------------|----------------------------------|--------------------------------------------|
| `AFRASHODAN_ADDR` | `:8080`                          | listen address                             |
| `DATABASE_URL`    | local dev DSN                    | PostgreSQL connection string               |
| `JWT_SECRET`      | dev placeholder                  | HMAC signing key for session tokens        |
| `ADMIN_USER` / `ADMIN_PASSWORD`   | —                | bootstrap admin on first boot              |
| `DEMO_USER` / `DEMO_PASSWORD`     | —                | optional demo customer on first boot       |
| `AFRASHODAN_SEED` | —                                | `.nessus` file to seed the demo customer   |

## Layout

```
backend/
  main.go                     HTTP server, auth middleware, routes
  internal/
    nessus/  model, parse.go (Nessus v2 XML → []Host), store.go (search/stats)
    db/      db.go (pgx pool + migrations), users.go, hosts.go
    auth/    bcrypt passwords + HMAC-SHA256 JWT (stdlib) + tests
  data/sample.nessus          demo scan (2 hosts)
src/app/
  App.tsx     auth gate + customer search dashboard (Home / results / host)
  Login.tsx   login page
  Admin.tsx   admin panel (create customer, upload + assign, customer list)
  auth.tsx    React auth context (token persistence, session restore)
  api.ts      typed backend client (Bearer auth, scoped calls)
```

## Notes & next steps

- Uploads **accumulate**: re-uploading for a customer upserts by IP (newest wins) and
  keeps scan history. Change to full-replace in `db.SaveScan` if preferred.
- `JWT_SECRET`, `ADMIN_PASSWORD`, and the DB password are placeholders in
  `docker-compose.yml` — rotate them before any real deployment, and terminate TLS in
  front of nginx.
- Geo/ASN fields are placeholders for private networks; wire in a GeoIP/RDAP lookup if
  you scan public ranges.

> This project started from a Figma Make export of the UI and was extended into a
> multi-tenant platform: Go backend, real Nessus parsing, JWT auth, per-tenant scoping,
> an admin panel, and PostgreSQL persistence.
