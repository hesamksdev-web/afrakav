package main

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/afranet/afrashodan/internal/auth"
	"github.com/afranet/afrashodan/internal/db"
)

// scopeFor runs targetCustomer for a request carrying the given claims. It only
// covers the paths that decide access without touching the database.
func scopeFor(t *testing.T, url string, c auth.Claims) (int64, error) {
	t.Helper()
	r := httptest.NewRequest("GET", url, nil)
	r = r.WithContext(context.WithValue(r.Context(), claimsKey, c))
	return (&server{}).targetCustomer(r)
}

func TestCustomerCannotReadAnotherCustomer(t *testing.T) {
	got, err := scopeFor(t, "/api/hosts?customerId=99",
		auth.Claims{UserID: 7, Role: db.RoleCustomer})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 7 {
		t.Fatalf("customer 7 asking for customer 99 got scope %d, want 7", got)
	}
}

func TestAdminMustNameACustomer(t *testing.T) {
	if _, err := scopeFor(t, "/api/hosts", auth.Claims{UserID: 1, Role: db.RoleAdmin}); err == nil {
		t.Fatal("admin without customerId was allowed through")
	}
}

// An unknown role must be denied, not treated as an admin. Roles are constrained
// in the database today, so this guards the shape of the code: a future handler
// registered without the auth middleware gets zero-value claims, and those must
// not reach anyone's data.
func TestUnknownRoleIsDenied(t *testing.T) {
	for name, c := range map[string]auth.Claims{
		"empty role":        {UserID: 7, Role: ""},
		"unexpected role":   {UserID: 7, Role: "operator"},
		"zero-value claims": {},
	} {
		if _, err := scopeFor(t, "/api/hosts?customerId=99", c); !errors.Is(err, errForbidden) {
			t.Errorf("%s: got err %v, want errForbidden", name, err)
		}
	}
}
