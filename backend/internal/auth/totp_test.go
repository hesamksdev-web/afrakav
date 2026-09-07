package auth

import (
	"strings"
	"testing"
	"time"
)

// Secret "12345678901234567890" in base32 — the RFC 6238 appendix B key.
const rfcSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

func TestTOTPMatchesRFC6238Vectors(t *testing.T) {
	// The RFC prints eight digits; this implementation emits six, so the
	// expectations are the last six of each published value.
	cases := map[int64]string{
		59:          "287082",
		1111111109:  "081804",
		1111111111:  "050471",
		1234567890:  "005924",
		2000000000:  "279037",
		20000000000: "353130",
	}
	for unix, want := range cases {
		got, err := TOTPCode(rfcSecret, time.Unix(unix, 0))
		if err != nil {
			t.Fatalf("t=%d: %v", unix, err)
		}
		if got != want {
			t.Errorf("TOTPCode at t=%d = %s, want %s", unix, got, want)
		}
	}
}

func TestVerifyTOTPAcceptsDriftAndRejectsTheRest(t *testing.T) {
	now := time.Unix(1111111111, 0)
	current, _ := TOTPCode(rfcSecret, now)

	if _, ok := VerifyTOTP(rfcSecret, current, now); !ok {
		t.Error("the current code was rejected")
	}
	// One step either side is accepted for clock drift.
	for _, offset := range []time.Duration{-30 * time.Second, 30 * time.Second} {
		code, _ := TOTPCode(rfcSecret, now.Add(offset))
		if _, ok := VerifyTOTP(rfcSecret, code, now); !ok {
			t.Errorf("code from %v away was rejected", offset)
		}
	}
	// Two steps away is not.
	for _, offset := range []time.Duration{-90 * time.Second, 90 * time.Second} {
		code, _ := TOTPCode(rfcSecret, now.Add(offset))
		if _, ok := VerifyTOTP(rfcSecret, code, now); ok {
			t.Errorf("code from %v away was accepted", offset)
		}
	}
	for _, bad := range []string{"", "12345", "1234567", "abcdef", "000000 "} {
		if _, ok := VerifyTOTP(rfcSecret, bad, now); ok {
			t.Errorf("malformed code %q was accepted", bad)
		}
	}
}

// The step is what the caller stores to stop the same code being replayed while
// it is still inside its window.
func TestVerifyTOTPReturnsTheStep(t *testing.T) {
	now := time.Unix(1111111111, 0)
	code, _ := TOTPCode(rfcSecret, now)
	step, ok := VerifyTOTP(rfcSecret, code, now)
	if !ok {
		t.Fatal("code rejected")
	}
	if want := now.Unix() / 30; step != want {
		t.Errorf("step = %d, want %d", step, want)
	}
}

func TestNewTOTPSecretIsUsableAndUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 5; i++ {
		secret, err := NewTOTPSecret()
		if err != nil {
			t.Fatal(err)
		}
		if seen[secret] {
			t.Fatal("NewTOTPSecret repeated a value")
		}
		seen[secret] = true

		code, err := TOTPCode(secret, time.Now())
		if err != nil {
			t.Fatalf("generated secret does not produce codes: %v", err)
		}
		if _, ok := VerifyTOTP(secret, code, time.Now()); !ok {
			t.Error("a freshly generated secret failed to verify its own code")
		}
	}
}

func TestRecoveryCodes(t *testing.T) {
	codes, hashes, err := NewRecoveryCodes()
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != recoveryCodeCount || len(hashes) != recoveryCodeCount {
		t.Fatalf("got %d codes and %d hashes", len(codes), len(hashes))
	}
	for i, code := range codes {
		if HashRecoveryCode(code) != hashes[i] {
			t.Errorf("code %d does not hash to its stored hash", i)
		}
	}
	// Formatting must not matter when someone types the code back in.
	plain := codes[0]
	for _, variant := range []string{
		plain,
		"  " + plain + "  ",
		strings.ToUpper(plain),
		strings.ReplaceAll(plain, "-", ""),
	} {
		if HashRecoveryCode(variant) != hashes[0] {
			t.Errorf("variant %q did not match the stored hash", variant)
		}
	}
}

func TestProvisioningURI(t *testing.T) {
	uri := TOTPProvisioningURI(rfcSecret, "acme-corp", "Afrakav")
	for _, want := range []string{
		"otpauth://totp/Afrakav:acme-corp?",
		"secret=" + rfcSecret,
		"issuer=Afrakav",
		"digits=6",
		"period=30",
	} {
		if !strings.Contains(uri, want) {
			t.Errorf("provisioning URI %q is missing %q", uri, want)
		}
	}
}

// The token handed out between the password step and the second-factor step
// must be distinguishable from a session token; treating one as the other would
// let a password alone sign someone in.
func TestChallengeTokenIsNotASessionToken(t *testing.T) {
	iss := NewIssuer("a-secret-long-enough-for-the-test", time.Hour)
	now := time.Unix(1700000000, 0)

	session, err := iss.Issue(7, "acme", RoleTest, 1, now)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := iss.IssueChallenge(7, "acme", RoleTest, 1, 5*time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	if session == challenge {
		t.Fatal("the two tokens are identical")
	}

	sc, err := iss.Parse(session, now)
	if err != nil || sc.Purpose != PurposeSession {
		t.Errorf("session token parsed as purpose %q (err %v)", sc.Purpose, err)
	}
	cc, err := iss.Parse(challenge, now)
	if err != nil || cc.Purpose != PurposeMFA {
		t.Errorf("challenge token parsed as purpose %q (err %v)", cc.Purpose, err)
	}

	// The challenge is short-lived even though the issuer's session TTL is long.
	if _, err := iss.Parse(challenge, now.Add(6*time.Minute)); err == nil {
		t.Error("the challenge token was still valid after its TTL")
	}
	if _, err := iss.Parse(session, now.Add(6*time.Minute)); err != nil {
		t.Error("the session token expired with the challenge TTL")
	}
}
