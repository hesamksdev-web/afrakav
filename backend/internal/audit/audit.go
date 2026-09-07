// Package audit defines the shape of a security event recorded by the
// platform. The persistence and hash-chaining live in internal/db, which is
// the only place allowed to touch the audit_events table; this package just
// keeps every call site describing an event the same way.
package audit

// Outcome is how an audited action ended.
type Outcome string

const (
	Success Outcome = "success"
	Failure Outcome = "failure"
	Denied  Outcome = "denied"
)

// Action names. Kept as constants so a typo does not silently create a new,
// unfiltered action in the log.
const (
	ActionLoginSuccess      = "login.success"
	ActionLoginFailed       = "login.failed"
	ActionLoginRefused      = "login.refused_disabled"
	ActionLoginMFAChallenge = "login.mfa_challenge"
	ActionLoginMFAFailed    = "login.mfa_failed"
	ActionLoginMFAReplay    = "login.mfa_replay"
	ActionRecoveryCodeUsed  = "login.recovery_code_used"
	ActionLogout            = "logout"

	ActionPasswordChanged       = "password.changed"
	ActionPasswordChangeRefused = "password.change_refused"
	ActionPasswordResetByAdmin  = "password.reset_by_admin"

	ActionTwoFactorSetupStarted = "2fa.setup_started"
	ActionTwoFactorEnabled      = "2fa.enabled"
	ActionTwoFactorDisabled     = "2fa.disabled"
	ActionTwoFactorDisableFail  = "2fa.disable_refused"
	ActionTwoFactorResetByAdmin = "2fa.reset_by_admin"

	ActionCustomerCreated   = "customer.created"
	ActionCustomerSuspended = "customer.suspended"
	ActionCustomerRestored  = "customer.restored"

	ActionRequestReceived  = "request.received"
	ActionRequestThrottled = "request.throttled"
	ActionRequestApproved  = "request.approved"
	ActionRequestRejected  = "request.rejected"

	ActionScanUploaded = "scan.uploaded"
	ActionScanDeleted  = "scan.deleted"

	ActionTenantViewed = "admin.tenant_viewed"

	ActionSystemStarted         = "system.started"
	ActionBootstrapAdminCreated = "system.bootstrap_admin_created"
	ActionBootstrapDemoSeeded   = "system.bootstrap_demo_seeded"
	ActionAuditLogViewed        = "audit.viewed"
)

// Event is what a handler hands to the audit recorder. ActorID/CustomerID of 0
// mean "not applicable", not "user 0".
type Event struct {
	ActorID       int64
	ActorUsername string
	ActorRole     string
	Action        string
	Outcome       Outcome
	TargetType    string
	TargetID      string
	TargetLabel   string
	CustomerID    int64
	IP            string
	UserAgent     string
	Details       map[string]any
}
