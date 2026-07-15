// Command afrashodan is the Go backend for the Afranet exposure-intelligence
// platform. It is multi-tenant: an admin uploads Nessus (.nessus) scans and
// assigns each to a customer; customers log in and see ONLY their own hosts.
//
// Public:
//
//	POST /api/login                 {username,password} -> {token,user}
//	GET  /api/health                liveness
//
// Authenticated (Bearer token):
//
//	GET  /api/me                    current user
//	GET  /api/hosts                 caller's hosts (admin: ?customerId=)
//	GET  /api/hosts/{ip}            one host, scoped
//	GET  /api/search?q=             Shodan-style query, scoped
//	GET  /api/stats                 dashboard aggregates, scoped
//	GET  /api/scans                 upload history, scoped
//
// Admin only:
//
//	GET  /api/admin/customers       list customers with counts
//	POST /api/admin/customers       {username,password,displayName}
//	POST /api/admin/upload          multipart: file=.nessus, customerId=<id>
package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/afranet/afrashodan/internal/auth"
	"github.com/afranet/afrashodan/internal/db"
	"github.com/afranet/afrashodan/internal/nessus"
)

const maxUploadBytes = 64 << 20 // 64 MiB

type server struct {
	db     *db.DB
	issuer *auth.Issuer
}

func main() {
	ctx := context.Background()

	addr := envOr("AFRASHODAN_ADDR", ":8080")
	dsn := envOr("DATABASE_URL", "postgres://afrashodan:afrashodan@localhost:5432/afrashodan?sslmode=disable")
	secret := envOr("JWT_SECRET", "dev-insecure-secret-change-me")

	database, err := db.Connect(ctx, dsn)
	if err != nil {
		log.Fatalf("database: %v", err)
	}
	defer database.Close()
	if err := database.Migrate(ctx); err != nil {
		log.Fatalf("migrate: %v", err)
	}

	srv := &server{
		db:     database,
		issuer: auth.NewIssuer(secret, 12*time.Hour),
	}
	srv.bootstrap(ctx)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", srv.handleHealth)
	mux.HandleFunc("POST /api/login", srv.handleLogin)

	mux.Handle("GET /api/me", srv.authed(srv.handleMe))
	mux.Handle("GET /api/hosts", srv.authed(srv.handleHosts))
	mux.Handle("GET /api/hosts/{ip}", srv.authed(srv.handleHost))
	mux.Handle("GET /api/search", srv.authed(srv.handleSearch))
	mux.Handle("GET /api/stats", srv.authed(srv.handleStats))
	mux.Handle("GET /api/scans", srv.authed(srv.handleScans))

	mux.Handle("GET /api/admin/customers", srv.adminOnly(srv.handleListCustomers))
	mux.Handle("POST /api/admin/customers", srv.adminOnly(srv.handleCreateCustomer))
	mux.Handle("POST /api/admin/upload", srv.adminOnly(srv.handleUpload))

	log.Printf("Afrashodan backend listening on %s", addr)
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           cors(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Fatal(httpSrv.ListenAndServe())
}

// bootstrap creates the initial admin (and an optional demo customer + seed
// scan) from environment variables the first time the platform runs.
func (s *server) bootstrap(ctx context.Context) {
	adminUser := os.Getenv("ADMIN_USER")
	adminPass := os.Getenv("ADMIN_PASSWORD")
	if adminUser != "" && adminPass != "" {
		if _, err := s.db.GetUserByUsername(ctx, adminUser); errors.Is(err, db.ErrNotFound) {
			hash, _ := auth.HashPassword(adminPass)
			if _, err := s.db.CreateUser(ctx, adminUser, hash, db.RoleAdmin, "Administrator"); err != nil {
				log.Printf("bootstrap admin: %v", err)
			} else {
				log.Printf("bootstrap: created admin %q", adminUser)
			}
		}
	}

	demoUser := os.Getenv("DEMO_USER")
	demoPass := os.Getenv("DEMO_PASSWORD")
	seedFile := os.Getenv("AFRASHODAN_SEED")
	if demoUser != "" && demoPass != "" {
		if _, err := s.db.GetUserByUsername(ctx, demoUser); errors.Is(err, db.ErrNotFound) {
			hash, _ := auth.HashPassword(demoPass)
			u, err := s.db.CreateUser(ctx, demoUser, hash, db.RoleCustomer, "Demo Customer")
			if err != nil {
				log.Printf("bootstrap demo: %v", err)
				return
			}
			log.Printf("bootstrap: created demo customer %q", demoUser)
			if seedFile != "" {
				if f, err := os.Open(seedFile); err == nil {
					defer f.Close()
					if hosts, err := nessus.Parse(f); err == nil {
						if _, err := s.db.SaveScan(ctx, u.ID, "sample.nessus", hosts); err == nil {
							log.Printf("bootstrap: seeded %d hosts for %q", len(hosts), demoUser)
						}
					}
				}
			}
		}
	}
}

// ── public handlers ─────────────────────────────────────────────────────────

func (s *server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	u, err := s.db.GetUserByUsername(r.Context(), strings.TrimSpace(body.Username))
	if err != nil || !auth.CheckPassword(u.PasswordHash, body.Password) {
		writeError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}
	token, err := s.issuer.Issue(u.ID, u.Username, u.Role, time.Now())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not issue token")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token": token,
		"user":  publicUser(u),
	})
}

// ── authenticated handlers ──────────────────────────────────────────────────

func (s *server) handleMe(w http.ResponseWriter, r *http.Request) {
	c := claimsFrom(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"user": map[string]any{"username": c.Username, "role": c.Role, "id": c.UserID},
	})
}

func (s *server) handleHosts(w http.ResponseWriter, r *http.Request) {
	cid, err := s.targetCustomer(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	hosts, err := s.db.ListHosts(r.Context(), cid)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load hosts")
		return
	}
	writeJSON(w, http.StatusOK, hosts)
}

func (s *server) handleHost(w http.ResponseWriter, r *http.Request) {
	cid, err := s.targetCustomer(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	h, err := s.db.GetHost(r.Context(), cid, r.PathValue("ip"))
	if errors.Is(err, db.ErrNotFound) {
		writeError(w, http.StatusNotFound, "host not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	writeJSON(w, http.StatusOK, h)
}

func (s *server) handleSearch(w http.ResponseWriter, r *http.Request) {
	cid, err := s.targetCustomer(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	hosts, err := s.db.ListHosts(r.Context(), cid)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load hosts")
		return
	}
	q := r.URL.Query().Get("q")
	results := nessus.SearchHosts(hosts, q)
	writeJSON(w, http.StatusOK, map[string]any{"query": q, "count": len(results), "results": results})
}

func (s *server) handleStats(w http.ResponseWriter, r *http.Request) {
	cid, err := s.targetCustomer(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	hosts, err := s.db.ListHosts(r.Context(), cid)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load hosts")
		return
	}
	writeJSON(w, http.StatusOK, nessus.ComputeStats(hosts, ""))
}

func (s *server) handleScans(w http.ResponseWriter, r *http.Request) {
	cid, err := s.targetCustomer(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	scans, err := s.db.ListScans(r.Context(), cid)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load scans")
		return
	}
	writeJSON(w, http.StatusOK, scans)
}

// ── admin handlers ──────────────────────────────────────────────────────────

func (s *server) handleListCustomers(w http.ResponseWriter, r *http.Request) {
	customers, err := s.db.ListCustomers(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list customers")
		return
	}
	writeJSON(w, http.StatusOK, customers)
}

func (s *server) handleCreateCustomer(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username    string `json:"username"`
		Password    string `json:"password"`
		DisplayName string `json:"displayName"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	body.Username = strings.TrimSpace(body.Username)
	if len(body.Username) < 3 || len(body.Password) < 6 {
		writeError(w, http.StatusUnprocessableEntity, "username must be at least 3 and password at least 6 characters")
		return
	}
	hash, err := auth.HashPassword(body.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "hash failed")
		return
	}
	u, err := s.db.CreateUser(r.Context(), body.Username, hash, db.RoleCustomer, body.DisplayName)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "unique") {
			writeError(w, http.StatusConflict, "this username is already taken")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not create customer")
		return
	}
	writeJSON(w, http.StatusCreated, publicUser(u))
}

func (s *server) handleUpload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	if err := r.ParseMultipartForm(maxUploadBytes); err != nil {
		writeError(w, http.StatusBadRequest, "file too large or malformed form (max 64 MiB)")
		return
	}
	customerID, err := strconv.ParseInt(r.FormValue("customerId"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "missing or invalid customerId")
		return
	}
	// Verify the target is a real customer.
	if u, err := s.db.GetUser(r.Context(), customerID); err != nil || u.Role != db.RoleCustomer {
		writeError(w, http.StatusBadRequest, "customer not found")
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, `missing multipart field "file"`)
		return
	}
	defer file.Close()

	hosts, err := nessus.Parse(file)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "could not parse Nessus file: "+err.Error())
		return
	}
	scan, err := s.db.SaveScan(r.Context(), customerID, header.Filename, hosts)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not save scan")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"scan":        scan,
		"hostsParsed": len(hosts),
	})
}

// ── scoping / middleware ────────────────────────────────────────────────────

type ctxKey int

const claimsKey ctxKey = 0

// targetCustomer resolves which customer's data a request should read: a
// customer always sees their own; an admin must pass ?customerId=.
func (s *server) targetCustomer(r *http.Request) (int64, error) {
	c := claimsFrom(r)
	if c.Role == db.RoleCustomer {
		return c.UserID, nil
	}
	// admin
	raw := r.URL.Query().Get("customerId")
	if raw == "" {
		return 0, errors.New("admin must specify customerId")
	}
	return strconv.ParseInt(raw, 10, 64)
}

func (s *server) authed(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, ok := s.verify(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), claimsKey, c)))
	})
}

func (s *server) adminOnly(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, ok := s.verify(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		if c.Role != db.RoleAdmin {
			writeError(w, http.StatusForbidden, "admin access required")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), claimsKey, c)))
	})
}

func (s *server) verify(r *http.Request) (auth.Claims, bool) {
	h := r.Header.Get("Authorization")
	token, ok := strings.CutPrefix(h, "Bearer ")
	if !ok {
		return auth.Claims{}, false
	}
	c, err := s.issuer.Parse(strings.TrimSpace(token), time.Now())
	if err != nil {
		return auth.Claims{}, false
	}
	return c, true
}

func claimsFrom(r *http.Request) auth.Claims {
	c, _ := r.Context().Value(claimsKey).(auth.Claims)
	return c
}

// ── helpers ─────────────────────────────────────────────────────────────────

func publicUser(u db.User) map[string]any {
	return map[string]any{
		"id":          u.ID,
		"username":    u.Username,
		"role":        u.Role,
		"displayName": u.DisplayName,
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
