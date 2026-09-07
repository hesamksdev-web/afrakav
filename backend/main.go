// Command afrakav is the Go backend for the Afranet vulnerability-management
// platform. It is multi-tenant: an admin uploads Nessus (.nessus) scans and
// assigns each to a customer; customers log in and see ONLY their own hosts.
//
// Public:
//
//	POST /api/login                 {username,password} -> {token,user}
//	                                or, with 2FA on, {mfaRequired,challenge}
//	POST /api/login/mfa             {challenge,code} -> {token,user}
//	POST /api/access-request        ask for an account; creates nothing
//	GET  /api/health                liveness
//
// Authenticated (Bearer token):
//
//	GET  /api/me                    current user
//	POST /api/logout                revoke this session's token
//	GET  /api/hosts                 caller's hosts (admin: ?customerId=)
//	GET  /api/hosts/{ip}            one host, scoped
//	GET  /api/search?q=             Shodan-style query, scoped
//	GET  /api/stats                 dashboard aggregates, scoped
//	GET  /api/scans                 upload history, scoped
//	GET  /api/events                caller's own security activity
//	POST /api/password              change your own password
//	POST /api/2fa/setup             begin enrolment -> {secret,uri}
//	POST /api/2fa/enable            {code} -> {token,recoveryCodes}
//	POST /api/2fa/disable           {password}
//
// Admin only:
//
//	GET  /api/admin/customers       list customers with counts
//	POST /api/admin/customers       {username,password,displayName}
//	POST /api/admin/upload          multipart: file=.nessus, customerId=<id>
//	POST /api/admin/scans/{id}/delete         {customerId} — undo an upload
//	POST /api/admin/customers/{id}/password   reset a customer's password
//	POST /api/admin/customers/{id}/status     suspend or restore an account
//	POST /api/admin/customers/{id}/2fa/reset  clear a locked-out second factor
//	GET  /api/admin/access-requests           pending sign-up requests
//	POST /api/admin/access-requests/{id}/approve  create the customer
//	POST /api/admin/access-requests/{id}/reject   decline it
//	GET  /api/admin/events                    the full security event log
package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/mail"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/afranet/afrashodan/internal/audit"
	"github.com/afranet/afrashodan/internal/auth"
	"github.com/afranet/afrashodan/internal/db"
	"github.com/afranet/afrashodan/internal/nessus"
)

const (
	maxUploadBytes = 64 << 20 // hard cap on an upload
	uploadMemory   = 8 << 20  // keep this much of it in RAM; the rest spills to disk
	minSecretLen   = 32       // shortest JWT_SECRET we will start with
	minUsernameLen = 3
	minPasswordLen = 12

	// How long the half-authenticated login has to produce a second factor.
	mfaChallengeTTL = 5 * time.Minute

	// The name an authenticator app shows beside the account.
	totpIssuer = "Afrakav"

	// Caps on the public access-request form. It is the one endpoint an
	// unauthenticated stranger can write through, so everything it accepts is
	// bounded and it is capped per address on top of the nginx rate limit.
	maxRequestField    = 200
	maxRequestNote     = 1000
	maxRequestsPerIP   = 5
	requestsPerIPSince = 24 * time.Hour
)

// dummyHash is compared against when a login names an account that does not
// exist, so a wrong username costs the same bcrypt work as a wrong password and
// the response time stops revealing which accounts are real.
var dummyHash, _ = auth.HashPassword("afrashodan-timing-equalizer")

// commonPasswords are rejected outright — length alone does not save a password
// an attacker tries first.
var commonPasswords = map[string]bool{
	"123456789012": true, "password1234": true, "qwertyuiop12": true,
	"adminadmin12": true, "afrashodan12": true, "changemeplease": true,
	"passwordpassword": true, "administrator": true, "letmeinplease": true,
}

type server struct {
	db     *db.DB
	issuer *auth.Issuer
}

func main() {
	ctx := context.Background()

	addr := envOr("AFRASHODAN_ADDR", ":8080")
	dsn := mustEnv("DATABASE_URL")
	secret := mustEnv("JWT_SECRET")
	if len(secret) < minSecretLen {
		log.Fatalf("JWT_SECRET must be at least %d characters", minSecretLen)
	}

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
	mux.HandleFunc("POST /api/login/mfa", srv.handleLoginMFA)
	mux.HandleFunc("POST /api/access-request", srv.handleAccessRequest)

	mux.Handle("GET /api/me", srv.authed(srv.handleMe))
	mux.Handle("POST /api/logout", srv.authed(srv.handleLogout))
	mux.Handle("GET /api/hosts", srv.authed(srv.handleHosts))
	mux.Handle("GET /api/hosts/{ip}", srv.authed(srv.handleHost))
	mux.Handle("GET /api/search", srv.authed(srv.handleSearch))
	mux.Handle("GET /api/stats", srv.authed(srv.handleStats))
	mux.Handle("GET /api/scans", srv.authed(srv.handleScans))
	mux.Handle("GET /api/events", srv.authed(srv.handleMyEvents))
	mux.Handle("POST /api/password", srv.authed(srv.handleChangePassword))
	mux.Handle("POST /api/2fa/setup", srv.authed(srv.handleTOTPSetup))
	mux.Handle("POST /api/2fa/enable", srv.authed(srv.handleTOTPEnable))
	mux.Handle("POST /api/2fa/disable", srv.authed(srv.handleTOTPDisable))

	mux.Handle("GET /api/admin/customers", srv.adminOnly(srv.handleListCustomers))
	mux.Handle("POST /api/admin/customers", srv.adminOnly(srv.handleCreateCustomer))
	mux.Handle("POST /api/admin/upload", srv.adminOnly(srv.handleUpload))
	mux.Handle("POST /api/admin/scans/{id}/delete", srv.adminOnly(srv.handleDeleteScan))
	mux.Handle("POST /api/admin/customers/{id}/password", srv.adminOnly(srv.handleResetPassword))
	mux.Handle("POST /api/admin/customers/{id}/status", srv.adminOnly(srv.handleSetStatus))
	mux.Handle("POST /api/admin/customers/{id}/2fa/reset", srv.adminOnly(srv.handleResetTOTP))
	mux.Handle("GET /api/admin/access-requests", srv.adminOnly(srv.handleListAccessRequests))
	mux.Handle("POST /api/admin/access-requests/{id}/approve", srv.adminOnly(srv.handleApproveRequest))
	mux.Handle("POST /api/admin/access-requests/{id}/reject", srv.adminOnly(srv.handleRejectRequest))
	mux.Handle("GET /api/admin/events", srv.adminOnly(srv.handleAdminEvents))

	log.Printf("Afrashodan backend listening on %s", addr)
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Fatal(httpSrv.ListenAndServe())
}

// bootstrap creates the initial admin (and an optional demo customer + seed
// scan) from environment variables the first time the platform runs.
func (s *server) bootstrap(ctx context.Context) {
	if err := s.db.PruneExpiredRevocations(ctx); err != nil {
		log.Printf("bootstrap: prune revoked tokens: %v", err)
	}
	if err := s.db.RecordAuditEvent(ctx, audit.Event{Action: audit.ActionSystemStarted}); err != nil {
		log.Printf("bootstrap: could not record system.started: %v", err)
	}

	adminUser := os.Getenv("ADMIN_USER")
	adminPass := os.Getenv("ADMIN_PASSWORD")
	if adminUser != "" && adminPass != "" {
		if _, err := s.db.GetUserByUsername(ctx, adminUser); errors.Is(err, db.ErrNotFound) {
			if err := validatePassword(adminPass); err != nil {
				// Don't mint the platform's most privileged account from a weak
				// secret. Serving continues so an existing deployment is not
				// bricked by a bad .env, but the admin is not created.
				log.Printf("bootstrap: refusing to create admin %q — ADMIN_PASSWORD %v", adminUser, err)
				return
			}
			hash, _ := auth.HashPassword(adminPass)
			if u, err := s.db.CreateUser(ctx, adminUser, hash, db.RoleAdmin, "Administrator"); err != nil {
				log.Printf("bootstrap admin: %v", err)
			} else {
				log.Printf("bootstrap: created admin %q", adminUser)
				s.recordAuditBackground(ctx, audit.Event{
					Action: audit.ActionBootstrapAdminCreated, ActorID: u.ID, ActorUsername: u.Username, ActorRole: u.Role,
					TargetType: "user", TargetID: strconv.FormatInt(u.ID, 10), TargetLabel: u.Username,
				})
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
			s.recordAuditBackground(ctx, audit.Event{
				Action: audit.ActionCustomerCreated, ActorRole: db.RoleAdmin, ActorUsername: "bootstrap",
				TargetType: "user", TargetID: strconv.FormatInt(u.ID, 10), TargetLabel: u.Username, CustomerID: u.ID,
			})
			if seedFile != "" {
				if f, err := os.Open(seedFile); err == nil {
					defer f.Close()
					if hosts, err := nessus.Parse(f); err == nil {
						if scan, err := s.db.SaveScan(ctx, u.ID, "sample.nessus", hosts); err == nil {
							log.Printf("bootstrap: seeded %d hosts for %q", len(hosts), demoUser)
							s.recordAuditBackground(ctx, audit.Event{
								Action: audit.ActionBootstrapDemoSeeded, ActorRole: db.RoleAdmin, ActorUsername: "bootstrap",
								TargetType: "scan", TargetID: strconv.FormatInt(scan.ID, 10), TargetLabel: scan.Filename,
								CustomerID: u.ID, Details: map[string]any{"hosts": len(hosts)},
							})
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
	username := strings.TrimSpace(body.Username)
	u, err := s.db.GetUserByUsername(r.Context(), username)
	hash := u.PasswordHash
	if err != nil {
		hash = dummyHash // spend the same bcrypt time on a username that does not exist
	}
	if !auth.CheckPassword(hash, body.Password) || err != nil {
		s.recordAudit(r, audit.Event{
			Action: audit.ActionLoginFailed, Outcome: audit.Failure, ActorUsername: username,
		})
		writeError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}
	if u.Disabled {
		s.recordAudit(r, audit.Event{
			Action: audit.ActionLoginRefused, Outcome: audit.Denied,
			ActorID: u.ID, ActorUsername: u.Username, ActorRole: u.Role,
		})
		writeError(w, http.StatusForbidden, "this account is suspended")
		return
	}
	// With two-factor on, the password buys only a short-lived challenge that
	// authenticates nothing by itself.
	if u.TOTPEnabled {
		challenge, err := s.issuer.IssueChallenge(u.ID, u.Username, u.Role, u.TokenVersion, mfaChallengeTTL, time.Now())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not issue token")
			return
		}
		s.recordAudit(r, audit.Event{
			Action: audit.ActionLoginMFAChallenge, ActorID: u.ID, ActorUsername: u.Username, ActorRole: u.Role,
		})
		writeJSON(w, http.StatusOK, map[string]any{
			"mfaRequired": true,
			"challenge":   challenge,
		})
		return
	}

	token, err := s.issuer.Issue(u.ID, u.Username, u.Role, u.TokenVersion, time.Now())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not issue token")
		return
	}
	s.recordAudit(r, audit.Event{
		Action: audit.ActionLoginSuccess, ActorID: u.ID, ActorUsername: u.Username, ActorRole: u.Role,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"token": token,
		"user":  publicUser(u),
	})
}

// handleLoginMFA completes a login that stopped at the second factor. It accepts
// either a current authenticator code or one of the account's recovery codes.
func (s *server) handleLoginMFA(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Challenge string `json:"challenge"`
		Code      string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	c, err := s.issuer.Parse(strings.TrimSpace(body.Challenge), time.Now())
	if err != nil || c.Purpose != auth.PurposeMFA {
		writeError(w, http.StatusUnauthorized, "this sign-in has expired; start again")
		return
	}
	u, err := s.db.GetUser(r.Context(), c.UserID)
	if err != nil || u.Disabled || !u.TOTPEnabled || u.TokenVersion != c.Version {
		writeError(w, http.StatusUnauthorized, "this sign-in has expired; start again")
		return
	}

	if !s.checkSecondFactor(r, u, body.Code) {
		s.recordAudit(r, audit.Event{
			Action: audit.ActionLoginMFAFailed, Outcome: audit.Failure,
			ActorID: u.ID, ActorUsername: u.Username, ActorRole: u.Role,
		})
		writeError(w, http.StatusUnauthorized, "the verification code is not correct")
		return
	}

	// Re-read: consuming a recovery code may have changed nothing, but enabling
	// or disabling elsewhere would have, and the token must carry the current
	// version.
	fresh, err := s.db.GetUser(r.Context(), u.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not issue token")
		return
	}
	token, err := s.issuer.Issue(fresh.ID, fresh.Username, fresh.Role, fresh.TokenVersion, time.Now())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not issue token")
		return
	}
	s.recordAudit(r, audit.Event{
		Action: audit.ActionLoginSuccess, ActorID: fresh.ID, ActorUsername: fresh.Username, ActorRole: fresh.Role,
		Details: map[string]any{"secondFactor": true},
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"token": token,
		"user":  publicUser(fresh),
	})
}

// checkSecondFactor accepts a live authenticator code or burns a recovery code.
// A TOTP code is refused if it has already been used inside its own window.
func (s *server) checkSecondFactor(r *http.Request, u db.User, code string) bool {
	code = strings.TrimSpace(code)
	if code == "" {
		return false
	}

	if step, ok := auth.VerifyTOTP(u.TOTPSecret, code, time.Now()); ok {
		fresh, err := s.db.MarkTOTPStep(r.Context(), u.ID, step)
		if err != nil {
			log.Printf("second factor: recording step: %v", err)
			return false
		}
		if !fresh {
			s.recordAudit(r, audit.Event{
				Action: audit.ActionLoginMFAReplay, Outcome: audit.Denied,
				ActorID: u.ID, ActorUsername: u.Username, ActorRole: u.Role,
			})
		}
		return fresh
	}

	used, err := s.db.ConsumeRecoveryCode(r.Context(), u.ID, auth.HashRecoveryCode(code))
	if err != nil {
		log.Printf("second factor: consuming recovery code: %v", err)
		return false
	}
	if used {
		left, _ := s.db.CountRecoveryCodes(r.Context(), u.ID)
		s.recordAudit(r, audit.Event{
			Action: audit.ActionRecoveryCodeUsed, ActorID: u.ID, ActorUsername: u.Username, ActorRole: u.Role,
			Details: map[string]any{"remaining": left},
		})
	}
	return used
}

// ── access requests (public form + admin review) ────────────────────────────

// handleAccessRequest records a request for an account from the login page.
// It creates nothing and reveals nothing: the response is the same whether or
// not the company is already a customer.
func (s *server) handleAccessRequest(w http.ResponseWriter, r *http.Request) {
	var body struct {
		CompanyName    string `json:"companyName"`
		ContactName    string `json:"contactName"`
		Email          string `json:"email"`
		Phone          string `json:"phone"`
		WantedUsername string `json:"wantedUsername"`
		Note           string `json:"note"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8<<10)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req := db.AccessRequest{
		CompanyName:    strings.TrimSpace(body.CompanyName),
		ContactName:    strings.TrimSpace(body.ContactName),
		Email:          strings.TrimSpace(body.Email),
		Phone:          strings.TrimSpace(body.Phone),
		WantedUsername: strings.ToLower(strings.TrimSpace(body.WantedUsername)),
		Note:           strings.TrimSpace(body.Note),
		SourceIP:       clientIP(r),
	}
	if err := validateAccessRequest(&req); err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}

	// Second line of defence behind the nginx rate limit: a shared office
	// address should not be able to bury the admin panel.
	since := time.Now().Add(-requestsPerIPSince)
	if n, err := s.db.CountPendingRequestsSince(r.Context(), req.SourceIP, since); err == nil && n >= maxRequestsPerIP {
		s.recordAudit(r, audit.Event{
			Action: audit.ActionRequestThrottled, Outcome: audit.Denied,
			Details: map[string]any{"existing": n},
		})
		writeError(w, http.StatusTooManyRequests, "too many requests from this address; please try again later")
		return
	}

	saved, err := s.db.CreateAccessRequest(r.Context(), req)
	if err != nil {
		log.Printf("access request: %v", err)
		writeError(w, http.StatusInternalServerError, "could not submit the request")
		return
	}
	s.recordAudit(r, audit.Event{
		Action: audit.ActionRequestReceived, TargetType: "access_request",
		TargetID: strconv.FormatInt(saved.ID, 10), TargetLabel: saved.CompanyName,
		Details: map[string]any{"email": saved.Email},
	})
	writeJSON(w, http.StatusCreated, map[string]any{"status": "received"})
}

// validateAccessRequest bounds every field before it reaches the database.
func validateAccessRequest(a *db.AccessRequest) error {
	type field struct {
		value string
		min   int
		max   int
		msg   string
	}
	for _, f := range []field{
		{a.CompanyName, 2, maxRequestField, "please give the organisation name"},
		{a.ContactName, 2, maxRequestField, "please give a contact name"},
		{a.Phone, 5, 40, "please give a valid phone number"},
	} {
		if n := len([]rune(f.value)); n < f.min || n > f.max {
			return errors.New(f.msg)
		}
	}
	if len([]rune(a.Email)) > maxRequestField {
		return errors.New("please give a valid email address")
	}
	if _, err := mail.ParseAddress(a.Email); err != nil {
		return errors.New("please give a valid email address")
	}
	if a.WantedUsername != "" && !validUsername(a.WantedUsername) {
		return errors.New("the preferred username may use only letters, digits, dot, dash and underscore")
	}
	if len([]rune(a.Note)) > maxRequestNote {
		return errors.New("the note is too long")
	}
	return nil
}

// validUsername keeps usernames to a predictable shape, for both the request
// form and account creation.
func validUsername(u string) bool {
	if n := len([]rune(u)); n < minUsernameLen || n > 40 {
		return false
	}
	for _, r := range u {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}

func (s *server) handleListAccessRequests(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	switch status {
	case "", db.RequestPending, db.RequestApproved, db.RequestRejected:
	default:
		writeError(w, http.StatusBadRequest, "unknown status filter")
		return
	}
	list, err := s.db.ListAccessRequests(r.Context(), status)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load the requests")
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// handleApproveRequest creates the customer account the request asked for. The
// admin chooses the final username and password — nothing the visitor typed is
// used as a credential.
func (s *server) handleApproveRequest(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid request id")
		return
	}
	var body struct {
		Username    string `json:"username"`
		Password    string `json:"password"`
		DisplayName string `json:"displayName"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	body.Username = strings.ToLower(strings.TrimSpace(body.Username))
	if !validUsername(body.Username) {
		writeError(w, http.StatusUnprocessableEntity, "username must be at least 3 characters")
		return
	}
	if err := validatePassword(body.Password); err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	hash, err := auth.HashPassword(body.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "hash failed")
		return
	}

	admin := claimsFrom(r).Username
	u, err := s.db.ApproveAccessRequest(r.Context(), id, admin, body.Username, hash, strings.TrimSpace(body.DisplayName))
	if errors.Is(err, db.ErrNotFound) {
		writeError(w, http.StatusConflict, "this request has already been handled")
		return
	}
	if err != nil {
		if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "unique") {
			writeError(w, http.StatusConflict, "this username is already taken")
			return
		}
		log.Printf("approve access request %d: %v", id, err)
		writeError(w, http.StatusInternalServerError, "could not create the customer")
		return
	}
	s.recordAudit(r, audit.Event{
		Action: audit.ActionRequestApproved, TargetType: "access_request", TargetID: strconv.FormatInt(id, 10),
		TargetLabel: u.Username, CustomerID: u.ID,
	})
	writeJSON(w, http.StatusCreated, publicUser(u))
}

func (s *server) handleRejectRequest(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid request id")
		return
	}
	admin := claimsFrom(r).Username
	if err := s.db.RejectAccessRequest(r.Context(), id, admin); err != nil {
		if errors.Is(err, db.ErrNotFound) {
			writeError(w, http.StatusConflict, "this request has already been handled")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not update the request")
		return
	}
	s.recordAudit(r, audit.Event{
		Action: audit.ActionRequestRejected, TargetType: "access_request", TargetID: strconv.FormatInt(id, 10),
	})
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

// ── authenticated handlers ──────────────────────────────────────────────────

func (s *server) handleMe(w http.ResponseWriter, r *http.Request) {
	u, err := s.db.GetUser(r.Context(), claimsFrom(r).UserID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	left, _ := s.db.CountRecoveryCodes(r.Context(), u.ID)
	writeJSON(w, http.StatusOK, map[string]any{
		"user":                   publicUser(u),
		"recoveryCodesRemaining": left,
	})
}

// handleLogout ends the caller's own session: it denies this token's jti until
// it would have expired anyway, so it stops working immediately rather than
// only once the client discards it.
func (s *server) handleLogout(w http.ResponseWriter, r *http.Request) {
	c := claimsFrom(r)
	if err := s.db.RevokeToken(r.Context(), c.JTI, c.UserID, time.Unix(c.Exp, 0)); err != nil {
		writeError(w, http.StatusInternalServerError, "could not sign out")
		return
	}
	s.recordAudit(r, audit.Event{
		Action: audit.ActionLogout, ActorID: c.UserID, ActorUsername: c.Username, ActorRole: c.Role,
	})
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

// handleMyEvents returns the caller's own security activity — logins, password
// and two-factor changes, and the like — cursor-paginated newest first.
func (s *server) handleMyEvents(w http.ResponseWriter, r *http.Request) {
	c := claimsFrom(r)
	cursor, _ := strconv.ParseInt(r.URL.Query().Get("cursor"), 10, 64)
	events, err := s.db.ListAuditEventsForActor(r.Context(), c.UserID, cursor, 50)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load activity")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

func (s *server) handleHosts(w http.ResponseWriter, r *http.Request) {
	cid, err := s.targetCustomer(r)
	if err != nil {
		writeScopeError(w, err)
		return
	}
	s.auditTenantView(r, cid)
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
		writeScopeError(w, err)
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
		writeScopeError(w, err)
		return
	}
	s.auditTenantView(r, cid)
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
		writeScopeError(w, err)
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
		writeScopeError(w, err)
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

// handleAdminEvents serves the security event log to the admin panel: every
// login, logout, admin action, and tenant-data view, filtered and paginated.
// Reading the log is itself audited, so "who looked at the audit log" is
// answerable from the log.
func (s *server) handleAdminEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := db.AuditFilter{
		Action:    q.Get("action"),
		Outcome:   q.Get("outcome"),
		ActorLike: q.Get("actor"),
	}
	if v := q.Get("customerId"); v != "" {
		f.CustomerID, _ = strconv.ParseInt(v, 10, 64)
	}
	if v := q.Get("cursor"); v != "" {
		f.Cursor, _ = strconv.ParseInt(v, 10, 64)
	}
	if v := q.Get("since"); v != "" {
		f.Since, _ = time.Parse(time.RFC3339, v)
	}
	if v := q.Get("until"); v != "" {
		f.Until, _ = time.Parse(time.RFC3339, v)
	}
	events, err := s.db.ListAuditEvents(r.Context(), f)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load events")
		return
	}
	s.recordAudit(r, audit.Event{Action: audit.ActionAuditLogViewed})
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

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
	body.Username = strings.ToLower(strings.TrimSpace(body.Username))
	if !validUsername(body.Username) {
		writeError(w, http.StatusUnprocessableEntity, "username must be at least 3 characters")
		return
	}
	if err := validatePassword(body.Password); err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
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
	s.recordAudit(r, audit.Event{
		Action: audit.ActionCustomerCreated, TargetType: "user",
		TargetID: strconv.FormatInt(u.ID, 10), TargetLabel: u.Username, CustomerID: u.ID,
	})
	writeJSON(w, http.StatusCreated, publicUser(u))
}

func (s *server) handleUpload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	if err := r.ParseMultipartForm(uploadMemory); err != nil {
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
		log.Printf("upload: parsing %q failed: %v", header.Filename, err)
		writeError(w, http.StatusUnprocessableEntity, "could not parse the Nessus file")
		return
	}
	scan, err := s.db.SaveScan(r.Context(), customerID, header.Filename, hosts)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not save scan")
		return
	}
	s.recordAudit(r, audit.Event{
		Action: audit.ActionScanUploaded, TargetType: "scan", TargetID: strconv.FormatInt(scan.ID, 10),
		TargetLabel: header.Filename, CustomerID: customerID,
		Details: map[string]any{"hosts": len(hosts)},
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"scan":        scan,
		"hostsParsed": len(hosts),
	})
}

// handleDeleteScan undoes an upload made to the wrong customer, or one whose
// hosts should never have merged into the tenant's current view. Only the
// hosts still pointing at this scan as their most recent upload are removed —
// a host later touched by a different scan is left alone.
func (s *server) handleDeleteScan(w http.ResponseWriter, r *http.Request) {
	scanID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid scan id")
		return
	}
	var body struct {
		CustomerID int64 `json:"customerId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.CustomerID == 0 {
		writeError(w, http.StatusBadRequest, "missing or invalid customerId")
		return
	}
	removed, err := s.db.DeleteScan(r.Context(), body.CustomerID, scanID)
	if errors.Is(err, db.ErrNotFound) {
		writeError(w, http.StatusNotFound, "scan not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not delete the scan")
		return
	}
	s.recordAudit(r, audit.Event{
		Action: audit.ActionScanDeleted, TargetType: "scan", TargetID: strconv.FormatInt(scanID, 10),
		CustomerID: body.CustomerID, Details: map[string]any{"hostsRemoved": removed},
	})
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "hostsRemoved": removed})
}

// ── account management ──────────────────────────────────────────────────────

// validatePassword enforces the account password policy. Length is the control
// that matters most here, since /api/login is rate-limited but not unguessable.
func validatePassword(p string) error {
	if len([]rune(p)) < minPasswordLen {
		return errors.New("password must be at least 12 characters")
	}
	if commonPasswords[strings.ToLower(strings.TrimSpace(p))] {
		return errors.New("this password is too easy to guess")
	}
	return nil
}

// handleChangePassword lets the signed-in user replace their own password.
func (s *server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	c := claimsFrom(r)
	u, err := s.db.GetUser(r.Context(), c.UserID)
	if err != nil || !auth.CheckPassword(u.PasswordHash, body.CurrentPassword) {
		s.recordAudit(r, audit.Event{
			Action: audit.ActionPasswordChangeRefused, Outcome: audit.Failure,
			ActorID: c.UserID, ActorUsername: c.Username, ActorRole: c.Role,
		})
		writeError(w, http.StatusUnauthorized, "current password is incorrect")
		return
	}
	if err := validatePassword(body.NewPassword); err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	hash, err := auth.HashPassword(body.NewPassword)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "hash failed")
		return
	}
	if err := s.db.SetPassword(r.Context(), u.ID, hash); err != nil {
		writeError(w, http.StatusInternalServerError, "could not change the password")
		return
	}
	// The change voided every token issued before it, this request's included,
	// so hand back a fresh one and keep the caller signed in.
	token, err := s.reissue(r, u.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not issue token")
		return
	}
	s.recordAudit(r, audit.Event{
		Action: audit.ActionPasswordChanged, ActorID: u.ID, ActorUsername: u.Username, ActorRole: u.Role,
	})
	writeJSON(w, http.StatusOK, map[string]any{"token": token})
}

// handleResetPassword lets an admin set a customer's password, which also signs
// that customer out of every session they had open.
func (s *server) handleResetPassword(w http.ResponseWriter, r *http.Request) {
	target, ok := s.customerFromPath(w, r)
	if !ok {
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := validatePassword(body.Password); err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	hash, err := auth.HashPassword(body.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "hash failed")
		return
	}
	if err := s.db.SetPassword(r.Context(), target.ID, hash); err != nil {
		writeError(w, http.StatusInternalServerError, "could not change the password")
		return
	}
	s.recordAudit(r, audit.Event{
		Action: audit.ActionPasswordResetByAdmin, TargetType: "user",
		TargetID: strconv.FormatInt(target.ID, 10), TargetLabel: target.Username, CustomerID: target.ID,
	})
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

// handleSetStatus suspends or restores a customer account.
func (s *server) handleSetStatus(w http.ResponseWriter, r *http.Request) {
	target, ok := s.customerFromPath(w, r)
	if !ok {
		return
	}
	var body struct {
		Disabled bool `json:"disabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := s.db.SetDisabled(r.Context(), target.ID, body.Disabled); err != nil {
		writeError(w, http.StatusInternalServerError, "could not update the account")
		return
	}
	action := audit.ActionCustomerRestored
	if body.Disabled {
		action = audit.ActionCustomerSuspended
	}
	s.recordAudit(r, audit.Event{
		Action: action, TargetType: "user", TargetID: strconv.FormatInt(target.ID, 10),
		TargetLabel: target.Username, CustomerID: target.ID,
	})
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

// handleResetTOTP switches a customer's second factor off. Without it, a
// customer who loses both their phone and their recovery codes has no way back
// in — nobody else can read the secret, by design.
func (s *server) handleResetTOTP(w http.ResponseWriter, r *http.Request) {
	target, ok := s.customerFromPath(w, r)
	if !ok {
		return
	}
	if err := s.db.DisableTOTP(r.Context(), target.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "could not turn two-factor off")
		return
	}
	s.recordAudit(r, audit.Event{
		Action: audit.ActionTwoFactorResetByAdmin, TargetType: "user",
		TargetID: strconv.FormatInt(target.ID, 10), TargetLabel: target.Username, CustomerID: target.ID,
	})
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

// customerFromPath resolves the {id} path segment to an existing customer.
// Admin accounts are deliberately not reachable this way.
func (s *server) customerFromPath(w http.ResponseWriter, r *http.Request) (db.User, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "missing or invalid customerId")
		return db.User{}, false
	}
	u, err := s.db.GetUser(r.Context(), id)
	if err != nil || u.Role != db.RoleCustomer {
		writeError(w, http.StatusNotFound, "customer not found")
		return db.User{}, false
	}
	return u, true
}

// ── two-factor enrolment ────────────────────────────────────────────────────

// handleTOTPSetup begins enrolment: it mints a secret and hands back the
// otpauth URI for the QR code. Two-factor is not on until handleTOTPEnable
// confirms the account can produce a code from it.
func (s *server) handleTOTPSetup(w http.ResponseWriter, r *http.Request) {
	u, err := s.db.GetUser(r.Context(), claimsFrom(r).UserID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if u.TOTPEnabled {
		writeError(w, http.StatusConflict, "two-factor authentication is already on")
		return
	}
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not start two-factor setup")
		return
	}
	if err := s.db.StartTOTPEnrolment(r.Context(), u.ID, secret); err != nil {
		writeError(w, http.StatusInternalServerError, "could not start two-factor setup")
		return
	}
	s.recordAudit(r, audit.Event{
		Action: audit.ActionTwoFactorSetupStarted, ActorID: u.ID, ActorUsername: u.Username, ActorRole: u.Role,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"secret": secret,
		"uri":    auth.TOTPProvisioningURI(secret, u.Username, totpIssuer),
	})
}

// handleTOTPEnable turns two-factor on once the account proves it holds the
// secret, and returns the recovery codes — the only time they are ever shown.
func (s *server) handleTOTPEnable(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	u, err := s.db.GetUser(r.Context(), claimsFrom(r).UserID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if u.TOTPEnabled {
		writeError(w, http.StatusConflict, "two-factor authentication is already on")
		return
	}
	if u.TOTPSecret == "" {
		writeError(w, http.StatusConflict, "start the two-factor setup first")
		return
	}
	step, ok := auth.VerifyTOTP(u.TOTPSecret, body.Code, time.Now())
	if !ok {
		writeError(w, http.StatusUnauthorized, "the verification code is not correct")
		return
	}

	codes, hashes, err := auth.NewRecoveryCodes()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not finish two-factor setup")
		return
	}
	if err := s.db.EnableTOTP(r.Context(), u.ID, step, hashes); err != nil {
		writeError(w, http.StatusInternalServerError, "could not finish two-factor setup")
		return
	}

	// Enabling bumped token_version, so this session's token is now stale.
	token, err := s.reissue(r, u.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not issue token")
		return
	}
	s.recordAudit(r, audit.Event{
		Action: audit.ActionTwoFactorEnabled, ActorID: u.ID, ActorUsername: u.Username, ActorRole: u.Role,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"token":         token,
		"recoveryCodes": codes,
	})
}

// handleTOTPDisable turns two-factor off. It asks for the password again rather
// than trusting the open session, because switching a second factor off is
// exactly what someone on a borrowed screen would try.
func (s *server) handleTOTPDisable(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	u, err := s.db.GetUser(r.Context(), claimsFrom(r).UserID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !auth.CheckPassword(u.PasswordHash, body.Password) {
		s.recordAudit(r, audit.Event{
			Action: audit.ActionTwoFactorDisableFail, Outcome: audit.Failure,
			ActorID: u.ID, ActorUsername: u.Username, ActorRole: u.Role,
		})
		writeError(w, http.StatusUnauthorized, "current password is incorrect")
		return
	}
	if err := s.db.DisableTOTP(r.Context(), u.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "could not turn two-factor off")
		return
	}
	token, err := s.reissue(r, u.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not issue token")
		return
	}
	s.recordAudit(r, audit.Event{
		Action: audit.ActionTwoFactorDisabled, ActorID: u.ID, ActorUsername: u.Username, ActorRole: u.Role,
	})
	writeJSON(w, http.StatusOK, map[string]any{"token": token})
}

// reissue mints a fresh session token after an operation that bumped the
// account's token_version, so the caller's own session survives it.
func (s *server) reissue(r *http.Request, userID int64) (string, error) {
	u, err := s.db.GetUser(r.Context(), userID)
	if err != nil {
		return "", err
	}
	return s.issuer.Issue(u.ID, u.Username, u.Role, u.TokenVersion, time.Now())
}

// ── scoping / middleware ────────────────────────────────────────────────────

type ctxKey int

const claimsKey ctxKey = 0

// errForbidden marks a scoping failure that must answer 403 rather than 400.
var errForbidden = errors.New("access denied")

// targetCustomer resolves which customer's data a request should read: a
// customer always sees their own (any ?customerId= they send is ignored); an
// admin must name an existing customer. Every other case is denied — a role the
// switch does not know about, or claims that never passed through the auth
// middleware, must never fall through to the admin branch.
func (s *server) targetCustomer(r *http.Request) (int64, error) {
	c := claimsFrom(r)
	switch c.Role {
	case db.RoleCustomer:
		return c.UserID, nil

	case db.RoleAdmin:
		raw := r.URL.Query().Get("customerId")
		if raw == "" {
			return 0, errors.New("admin must specify customerId")
		}
		id, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return 0, errors.New("missing or invalid customerId")
		}
		if u, err := s.db.GetUser(r.Context(), id); err != nil || u.Role != db.RoleCustomer {
			return 0, errors.New("customer not found")
		}
		return id, nil

	default:
		return 0, errForbidden
	}
}

// writeScopeError turns a targetCustomer failure into the right status code.
func writeScopeError(w http.ResponseWriter, err error) {
	if errors.Is(err, errForbidden) {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	writeError(w, http.StatusBadRequest, err.Error())
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

// verify authenticates a request. The token must carry a valid signature and be
// unexpired, and the account it names must still exist, still be enabled, and
// still sit on the token_version the token was minted with. That last check is
// what makes a password change or a suspension take effect at once rather than
// whenever the token happens to expire.
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
	// A challenge token from a half-finished login must never pass for a session.
	if c.Purpose != auth.PurposeSession {
		return auth.Claims{}, false
	}
	u, err := s.db.GetUser(r.Context(), c.UserID)
	if err != nil || u.Disabled || u.TokenVersion != c.Version || u.Role != c.Role {
		return auth.Claims{}, false
	}
	// A token whose jti was revoked (logout) must never work again, even
	// though its signature and token_version still check out.
	if revoked, err := s.db.IsTokenRevoked(r.Context(), c.JTI); err != nil || revoked {
		return auth.Claims{}, false
	}
	return c, true
}

func claimsFrom(r *http.Request) auth.Claims {
	c, _ := r.Context().Value(claimsKey).(auth.Claims)
	return c
}

// ── audit logging ────────────────────────────────────────────────────────────

// recordAudit fills in what a handler already has for free — the caller's IP,
// user agent, and (if the request passed through the auth middleware) actor
// identity — then persists the event. It never fails the request: the log is
// a record of what happened, not a gate on whether it is allowed to happen,
// so a database hiccup here is only ever logged to stdout, not surfaced to
// the caller. The stdout line is a fallback route to a log shipper if the
// database write itself fails.
func (s *server) recordAudit(r *http.Request, e audit.Event) {
	if e.IP == "" {
		e.IP = clientIP(r)
	}
	if e.UserAgent == "" {
		e.UserAgent = r.UserAgent()
	}
	if e.ActorID == 0 {
		if c := claimsFrom(r); c.UserID != 0 {
			e.ActorID = c.UserID
			if e.ActorUsername == "" {
				e.ActorUsername = c.Username
			}
			if e.ActorRole == "" {
				e.ActorRole = c.Role
			}
		}
	}
	s.persistAudit(r.Context(), e)
}

// recordAuditBackground is for events with no HTTP request behind them —
// bootstrap actions run at process start.
func (s *server) recordAuditBackground(ctx context.Context, e audit.Event) {
	s.persistAudit(ctx, e)
}

func (s *server) persistAudit(ctx context.Context, e audit.Event) {
	outcome := e.Outcome
	if outcome == "" {
		outcome = audit.Success
	}
	log.Printf("audit: action=%s outcome=%s actor=%q actorId=%d target=%s:%s customer=%d ip=%s",
		e.Action, outcome, e.ActorUsername, e.ActorID, e.TargetType, e.TargetID, e.CustomerID, e.IP)
	if err := s.db.RecordAuditEvent(ctx, e); err != nil {
		log.Printf("audit: could not persist event action=%s: %v", e.Action, err)
	}
}

// auditTenantView records an admin reading a specific customer's data. It is a
// no-op for a customer viewing their own data — that is the expected path,
// not a cross-tenant access worth flagging.
func (s *server) auditTenantView(r *http.Request, customerID int64) {
	c := claimsFrom(r)
	if c.Role != db.RoleAdmin {
		return
	}
	s.recordAudit(r, audit.Event{
		Action: audit.ActionTenantViewed, CustomerID: customerID,
		TargetType: "customer", TargetID: strconv.FormatInt(customerID, 10),
	})
}

// ── helpers ─────────────────────────────────────────────────────────────────

func publicUser(u db.User) map[string]any {
	return map[string]any{
		"id":          u.ID,
		"username":    u.Username,
		"role":        u.Role,
		"displayName": u.DisplayName,
		"disabled":    u.Disabled,
		"totpEnabled": u.TOTPEnabled,
	}
}

// mustEnv reads a required setting and stops the process when it is missing.
// Credentials must never have a built-in fallback: a default that lives in the
// source is a default anyone can read.
func mustEnv(key string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		log.Fatalf("%s is required — set it in the .env file next to docker-compose.yml", key)
	}
	return v
}

// clientIP reports the caller's address, preferring the first hop nginx records
// in X-Forwarded-For. Only nginx talks to this service, so the header is ours.
func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		if first, _, ok := strings.Cut(fwd, ","); ok {
			return strings.TrimSpace(first)
		}
		return strings.TrimSpace(fwd)
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
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
