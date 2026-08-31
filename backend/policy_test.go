package main

import "testing"

func TestPasswordPolicy(t *testing.T) {
	rejected := []string{
		"",             // empty
		"short",        // far too short
		"elevenchars",  // 11 — one short of the minimum
		"password1234", // long enough but on the common list
		"ADMINADMIN12", // common list is case-insensitive
	}
	for _, p := range rejected {
		if err := validatePassword(p); err == nil {
			t.Errorf("validatePassword(%q) accepted it, want rejection", p)
		}
	}

	accepted := []string{
		"correct-horse-battery",
		"aVeryLongPassphrase!",
		"رمزعبوربسیارطولانی", // 12+ runes, counted as characters not bytes
	}
	for _, p := range accepted {
		if err := validatePassword(p); err != nil {
			t.Errorf("validatePassword(%q) = %v, want accepted", p, err)
		}
	}
}
