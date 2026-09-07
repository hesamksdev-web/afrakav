# Afranet — Afrakav

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
cp .env.example .env    # then fill in the secrets
docker compose up -d --build
```

- UI:          http://localhost:8081
- Backend API: http://localhost:8080 (also at http://localhost:8081/api)

On a server use `./deploy.sh`, which selects `docker-compose.prod.yml` (and
`docker-compose.tls.yml` once `certs/` exists) instead of the development
overrides. See `scripts/gen-certs.sh` for the certificate.

**Accounts** come from `.env` (see `.env.example`); there are no built-in
defaults. `ADMIN_USER`/`ADMIN_PASSWORD` create the admin on first boot, and the
optional `DEMO_USER`/`DEMO_PASSWORD` seed a customer with the bundled sample
scan. Passwords must be at least 12 characters, and `JWT_SECRET` at least 32 —
the backend refuses to start without them.

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
export JWT_SECRET="local-development-only-secret-not-for-servers"
export ADMIN_USER=admin ADMIN_PASSWORD=local-dev-admin-pass
export DEMO_USER=demo DEMO_PASSWORD=local-dev-demo-pass AFRASHODAN_SEED=data/sample.nessus
go run .
```

```bash
pnpm install
VITE_API_URL=http://localhost:8080 pnpm dev   # Vite dev server on :5173
```

## Access requests

The login page carries a public **درخواست دسترسی** form. A visitor submits their
organisation, contact details and an optional preferred username; the request is
stored and nothing else happens. An admin reviews it in the panel and, on
approval, picks the username and password themselves — nothing typed into the
public form ever becomes a credential. Approval creates the account and marks
the request in one transaction, so two admins acting at once cannot produce two
accounts from one request.

The form is the only endpoint an unauthenticated stranger can write through, so
it is bounded on three sides: nginx rate-limits it to three a minute per
address, the backend caps five per address per day, and every field has a length
limit with the email parsed rather than pattern-matched.

## Two-factor authentication

Any account can turn on TOTP two-factor from **تنظیمات** (Settings). Enrolment
mints a secret, shows it as a QR code rendered in the browser, and only switches
two-factor on once the account produces a valid code — a half-finished enrolment
cannot lock anyone out. Enabling returns ten single-use recovery codes, shown
once and stored only as SHA-256 hashes.

With two-factor on, `POST /api/login` answers with a five-minute *challenge*
rather than a session token. The challenge carries a distinct purpose claim and
is refused everywhere a session token is expected, so a password alone signs
nobody in. `POST /api/login/mfa` accepts either a live code or a recovery code
and returns the real token. A code that has already been used inside its own
30-second window is rejected, and nginx rate-limits the whole `/api/login`
prefix so a six-digit code cannot be walked.

If a customer loses both their authenticator and their recovery codes, an admin
clears the second factor from the customer row in the admin panel; nobody can
read the secret back out.

## Backend API

Public:

| Method | Path            | Description                                  |
|--------|-----------------|----------------------------------------------|
| POST   | `/api/login`    | `{username,password}` → `{token, user}`, or `{mfaRequired, challenge}` |
| POST   | `/api/login/mfa`| `{challenge, code}` → `{token, user}`        |
| POST   | `/api/access-request` | ask for an account; creates nothing   |
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
| POST   | `/api/password`    | `{currentPassword,newPassword}` → a replacement token   |
| POST   | `/api/2fa/setup`   | begin enrolment → `{secret, uri}`                       |
| POST   | `/api/2fa/enable`  | `{code}` → `{token, recoveryCodes}`                     |
| POST   | `/api/2fa/disable` | `{password}`                                            |

Admin only:

| Method | Path                     | Description                                       |
|--------|--------------------------|---------------------------------------------------|
| GET    | `/api/admin/customers`   | list customers with host/scan counts              |
| POST   | `/api/admin/customers`   | `{username,password,displayName}`                 |
| POST   | `/api/admin/upload`      | multipart: `file=.nessus`, `customerId=<id>`      |
| POST   | `/api/admin/customers/{id}/password` | `{password}` — also ends that customer's sessions |
| POST   | `/api/admin/customers/{id}/status`   | `{disabled}` — suspend or restore an account      |
| POST   | `/api/admin/customers/{id}/2fa/reset`| clear a second factor the customer is locked out of |
| GET    | `/api/admin/access-requests`         | `?status=pending|approved|rejected`, newest first |
| POST   | `/api/admin/access-requests/{id}/approve` | `{username,password,displayName}` → creates the customer |
| POST   | `/api/admin/access-requests/{id}/reject`  | decline a pending request        |

**Search grammar:** `port:445`, `tag:rdp`, `vuln:CVE-2021-44228`, `cve:…`,
`product:jenkins`, `os:windows`, `subnet:10.20.30` (a /24, `net:` also works),
`has:exploit`, `has:malware`, `has:critical`, `exploit:true|false`, `*` for
everything, or a bare term matching IP / hostname / domain / OS / org / port /
service / CVE / plugin name.

**Exploit intelligence:** the parser reads `exploit_available`,
`exploited_by_malware`, `exploitability_ease` and the framework tags
(`exploit_framework_metasploit` and friends) from each Nessus finding. Findings
with a published exploit are surfaced on the customer dashboard ahead of
everything else, because CVSS alone does not tell you what is weaponised.

**No geolocation:** a `.nessus` file records no country, city, ISP or ASN, so the
platform does not display any. A host's place in the network is described by its
`/24` subnet and its operating system, both derived from the scan itself.

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
