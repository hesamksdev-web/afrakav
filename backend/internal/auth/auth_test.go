package auth

import (
	"testing"
	"time"
)

func TestTokenRoundTrip(t *testing.T) {
	iss := NewIssuer("secret", time.Hour)
	now := time.Unix(1_700_000_000, 0)

	tok, err := iss.Issue(42, "acme", RoleTest, 1, now)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	c, err := iss.Parse(tok, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if c.UserID != 42 || c.Username != "acme" || c.Role != RoleTest {
		t.Fatalf("claims mismatch: %+v", c)
	}
}

func TestExpiredToken(t *testing.T) {
	iss := NewIssuer("secret", time.Minute)
	now := time.Unix(1_700_000_000, 0)
	tok, _ := iss.Issue(1, "u", RoleTest, 1, now)
	if _, err := iss.Parse(tok, now.Add(2*time.Minute)); err == nil {
		t.Fatal("expected expired token to be rejected")
	}
}

func TestTamperedToken(t *testing.T) {
	iss := NewIssuer("secret", time.Hour)
	other := NewIssuer("different-secret", time.Hour)
	now := time.Unix(1_700_000_000, 0)
	tok, _ := iss.Issue(1, "u", RoleTest, 1, now)
	if _, err := other.Parse(tok, now); err == nil {
		t.Fatal("expected signature check to fail under a different secret")
	}
}

func TestPasswordHashing(t *testing.T) {
	h, err := HashPassword("s3cret-pass")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if !CheckPassword(h, "s3cret-pass") {
		t.Fatal("correct password rejected")
	}
	if CheckPassword(h, "wrong") {
		t.Fatal("wrong password accepted")
	}
}

const RoleTest = "customer"
