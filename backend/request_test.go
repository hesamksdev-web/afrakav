package main

import (
	"strings"
	"testing"

	"github.com/afranet/afrashodan/internal/db"
)

func validRequest() db.AccessRequest {
	return db.AccessRequest{
		CompanyName: "شرکت نمونه",
		ContactName: "امیررضا احمدی",
		Email:       "ops@example.com",
		Phone:       "02112345678",
	}
}

func TestAccessRequestValidationAcceptsAGoodForm(t *testing.T) {
	req := validRequest()
	req.WantedUsername = "acme-corp"
	req.Note = "دو رنج /24 داریم"
	if err := validateAccessRequest(&req); err != nil {
		t.Errorf("a complete form was rejected: %v", err)
	}
	// The optional fields really are optional.
	bare := validRequest()
	if err := validateAccessRequest(&bare); err != nil {
		t.Errorf("a form without the optional fields was rejected: %v", err)
	}
}

func TestAccessRequestValidationRejectsBadInput(t *testing.T) {
	cases := map[string]func(*db.AccessRequest){
		"empty company":      func(a *db.AccessRequest) { a.CompanyName = "" },
		"one-letter company": func(a *db.AccessRequest) { a.CompanyName = "x" },
		"oversized company":  func(a *db.AccessRequest) { a.CompanyName = strings.Repeat("ا", maxRequestField+1) },
		"empty contact":      func(a *db.AccessRequest) { a.ContactName = "" },
		"empty email":        func(a *db.AccessRequest) { a.Email = "" },
		"malformed email":    func(a *db.AccessRequest) { a.Email = "not-an-address" },
		"oversized email":    func(a *db.AccessRequest) { a.Email = strings.Repeat("a", maxRequestField) + "@example.com" },
		"short phone":        func(a *db.AccessRequest) { a.Phone = "12" },
		"bad username":       func(a *db.AccessRequest) { a.WantedUsername = "acme corp!" },
		"oversized note":     func(a *db.AccessRequest) { a.Note = strings.Repeat("ن", maxRequestNote+1) },
	}
	for name, mutate := range cases {
		req := validRequest()
		mutate(&req)
		if err := validateAccessRequest(&req); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestValidUsername(t *testing.T) {
	for _, ok := range []string{"acme", "acme-corp", "acme_corp", "acme.corp", "a1b2c3"} {
		if !validUsername(ok) {
			t.Errorf("validUsername(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{
		"", "ab", "acme corp", "acme/corp", "acme@corp", "شرکت",
		strings.Repeat("a", 41),
	} {
		if validUsername(bad) {
			t.Errorf("validUsername(%q) = true, want false", bad)
		}
	}
}
