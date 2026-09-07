package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Time-based one-time passwords, RFC 6238: HMAC-SHA1 over a 30-second counter,
// truncated to six digits. Implemented on the standard library so the platform
// carries no extra dependency for it, matching the token code above.
const (
	totpPeriod  = 30 * time.Second
	totpDigits  = 6
	totpSkew    = 1  // accept the neighbouring steps, for clock drift
	secretBytes = 20 // 160 bits, the size RFC 4226 recommends for HMAC-SHA1
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns a fresh base32 secret to be shared with an
// authenticator app.
func NewTOTPSecret() (string, error) {
	buf := make([]byte, secretBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return b32.EncodeToString(buf), nil
}

// TOTPCode computes the code for a secret at a point in time. Exported so tests
// and the enrolment flow can both use it.
func TOTPCode(secret string, t time.Time) (string, error) {
	return codeForStep(secret, t.Unix()/int64(totpPeriod.Seconds()))
}

// VerifyTOTP checks a user-supplied code against the secret, allowing one step
// of clock drift either way. It returns the counter step the code belongs to so
// the caller can reject a replay of the same code inside its validity window.
func VerifyTOTP(secret, code string, t time.Time) (step int64, ok bool) {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits || secret == "" {
		return 0, false
	}
	now := t.Unix() / int64(totpPeriod.Seconds())
	for delta := int64(-totpSkew); delta <= totpSkew; delta++ {
		want, err := codeForStep(secret, now+delta)
		if err != nil {
			return 0, false
		}
		// Constant-time: a timing difference would leak how much of the code
		// was correct, one digit at a time.
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return now + delta, true
		}
	}
	return 0, false
}

func codeForStep(secret string, step int64) (string, error) {
	key, err := b32.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", fmt.Errorf("decode totp secret: %w", err)
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))

	mac := hmac.New(sha1.New, key)
	mac.Write(counter[:])
	sum := mac.Sum(nil)

	// Dynamic truncation (RFC 4226 §5.3).
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff

	mod := uint32(1)
	for i := 0; i < totpDigits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", totpDigits, value%mod), nil
}

// TOTPProvisioningURI builds the otpauth:// URI an authenticator app reads from
// a QR code.
func TOTPProvisioningURI(secret, account, issuer string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(totpDigits))
	q.Set("period", fmt.Sprint(int(totpPeriod.Seconds())))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// ── recovery codes ──────────────────────────────────────────────────────────

const (
	recoveryCodeCount = 10
	recoveryCodeBytes = 8 // 64 bits, printed as 16 hex characters
)

// NewRecoveryCodes returns codes to show the user once, alongside the hashes to
// store. The codes are random enough that a plain SHA-256 is sufficient here —
// unlike a password, there is nothing to guess.
func NewRecoveryCodes() (codes []string, hashes []string, err error) {
	for i := 0; i < recoveryCodeCount; i++ {
		buf := make([]byte, recoveryCodeBytes)
		if _, err := rand.Read(buf); err != nil {
			return nil, nil, err
		}
		raw := hex.EncodeToString(buf)
		// Grouped for legibility when someone copies it off a screen.
		code := raw[:4] + "-" + raw[4:8] + "-" + raw[8:12] + "-" + raw[12:]
		codes = append(codes, code)
		hashes = append(hashes, HashRecoveryCode(code))
	}
	return codes, hashes, nil
}

// HashRecoveryCode normalises and hashes a recovery code for storage and lookup.
func HashRecoveryCode(code string) string {
	norm := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
	sum := sha256.Sum256([]byte(norm))
	return hex.EncodeToString(sum[:])
}
