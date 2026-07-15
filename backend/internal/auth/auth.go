// Package auth handles password hashing (bcrypt) and stateless session tokens
// (compact HMAC-SHA256 JWTs implemented with the standard library, so no JWT
// dependency is needed).
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// HashPassword returns a bcrypt hash of a plaintext password.
func HashPassword(plain string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	return string(h), err
}

// CheckPassword reports whether plain matches the stored bcrypt hash.
func CheckPassword(hash, plain string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)) == nil
}

// Claims is the token payload.
type Claims struct {
	UserID   int64  `json:"uid"`
	Username string `json:"usr"`
	Role     string `json:"role"`
	Exp      int64  `json:"exp"` // unix seconds
}

// ErrInvalidToken is returned for malformed, tampered, or expired tokens.
var ErrInvalidToken = errors.New("invalid or expired token")

var b64 = base64.RawURLEncoding

// Issuer signs and verifies tokens with a shared secret.
type Issuer struct {
	secret []byte
	ttl    time.Duration
}

// NewIssuer builds an Issuer with the given secret and token lifetime.
func NewIssuer(secret string, ttl time.Duration) *Issuer {
	return &Issuer{secret: []byte(secret), ttl: ttl}
}

// Issue returns a signed token for a user. `now` is passed in for testability.
func (i *Issuer) Issue(userID int64, username, role string, now time.Time) (string, error) {
	header := b64.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	claims := Claims{
		UserID:   userID,
		Username: username,
		Role:     role,
		Exp:      now.Add(i.ttl).Unix(),
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	payload := b64.EncodeToString(payloadJSON)
	signingInput := header + "." + payload
	sig := i.sign(signingInput)
	return signingInput + "." + sig, nil
}

// Parse verifies a token's signature and expiry and returns its claims.
func (i *Issuer) Parse(token string, now time.Time) (Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, ErrInvalidToken
	}
	signingInput := parts[0] + "." + parts[1]
	expected := i.sign(signingInput)
	// Constant-time comparison.
	if !hmac.Equal([]byte(expected), []byte(parts[2])) {
		return Claims{}, ErrInvalidToken
	}
	raw, err := b64.DecodeString(parts[1])
	if err != nil {
		return Claims{}, ErrInvalidToken
	}
	var c Claims
	if err := json.Unmarshal(raw, &c); err != nil {
		return Claims{}, ErrInvalidToken
	}
	if now.Unix() >= c.Exp {
		return Claims{}, ErrInvalidToken
	}
	return c, nil
}

func (i *Issuer) sign(input string) string {
	mac := hmac.New(sha256.New, i.secret)
	mac.Write([]byte(input))
	return b64.EncodeToString(mac.Sum(nil))
}
