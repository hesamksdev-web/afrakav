// Package mitre maps Nessus findings onto MITRE ATT&CK techniques.
//
// A .nessus file carries no ATT&CK data — Tenable's own technique mapping
// lives in their cloud products, not in the export — so the mapping has to
// come from here. Two paths produce it, and every result says which one it
// came from:
//
//   - "weakness": the finding's own CWE, mapped through the well-established
//     weakness-to-technique relationships. Reportable as an external mapping.
//   - "rule": a curated rule matching the plugin family and name. This is our
//     judgement, not MITRE's, and is labelled as such in the API so nobody
//     mistakes it for an official mapping.
//
// The rule path exists because most findings in a real estate have no CVE and
// no CWE at all — default SNMP communities, untrusted certificates, enabled
// TRACE — and a CVE-only mapping would leave those hosts blank.
//
// This catalogue is a curated subset covering what Nessus actually reports,
// not the complete ATT&CK corpus. It is deliberately a plain table so it can
// be extended, or replaced wholesale with a generated dataset, without
// touching the logic.
package mitre

import (
	"fmt"
	"strings"
)

// Tactic names, spelled as ATT&CK spells them.
const (
	tacticRecon      = "Reconnaissance"
	tacticInitial    = "Initial Access"
	tacticExecution  = "Execution"
	tacticPersist    = "Persistence"
	tacticPrivEsc    = "Privilege Escalation"
	tacticEvasion    = "Defense Evasion"
	tacticCredential = "Credential Access"
	tacticDiscovery  = "Discovery"
	tacticLateral    = "Lateral Movement"
	tacticCollection = "Collection"
	tacticImpact     = "Impact"
)

// Technique is one ATT&CK technique or sub-technique.
type Technique struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Tactics []string `json:"tactics"`
	URL     string   `json:"url"`
}

// catalogue holds every technique this mapping can produce.
var catalogue = map[string]Technique{
	"T1018":     {Name: "Remote System Discovery", Tactics: []string{tacticDiscovery}},
	"T1021":     {Name: "Remote Services", Tactics: []string{tacticLateral}},
	"T1021.001": {Name: "Remote Desktop Protocol", Tactics: []string{tacticLateral}},
	"T1021.002": {Name: "SMB/Windows Admin Shares", Tactics: []string{tacticLateral}},
	"T1021.004": {Name: "SSH", Tactics: []string{tacticLateral}},
	"T1040":     {Name: "Network Sniffing", Tactics: []string{tacticCredential, tacticDiscovery}},
	"T1046":     {Name: "Network Service Discovery", Tactics: []string{tacticDiscovery}},
	"T1059":     {Name: "Command and Scripting Interpreter", Tactics: []string{tacticExecution}},
	"T1068":     {Name: "Exploitation for Privilege Escalation", Tactics: []string{tacticPrivEsc}},
	"T1078":     {Name: "Valid Accounts", Tactics: []string{tacticInitial, tacticPersist, tacticPrivEsc, tacticEvasion}},
	"T1078.001": {Name: "Default Accounts", Tactics: []string{tacticInitial, tacticPersist, tacticPrivEsc, tacticEvasion}},
	"T1082":     {Name: "System Information Discovery", Tactics: []string{tacticDiscovery}},
	"T1083":     {Name: "File and Directory Discovery", Tactics: []string{tacticDiscovery}},
	"T1087":     {Name: "Account Discovery", Tactics: []string{tacticDiscovery}},
	"T1110":     {Name: "Brute Force", Tactics: []string{tacticCredential}},
	"T1133":     {Name: "External Remote Services", Tactics: []string{tacticInitial, tacticPersist}},
	"T1190":     {Name: "Exploit Public-Facing Application", Tactics: []string{tacticInitial}},
	"T1203":     {Name: "Exploitation for Client Execution", Tactics: []string{tacticExecution}},
	"T1210":     {Name: "Exploitation of Remote Services", Tactics: []string{tacticLateral}},
	"T1211":     {Name: "Exploitation for Defense Evasion", Tactics: []string{tacticEvasion}},
	"T1212":     {Name: "Exploitation for Credential Access", Tactics: []string{tacticCredential}},
	"T1499":     {Name: "Endpoint Denial of Service", Tactics: []string{tacticImpact}},
	"T1505.003": {Name: "Web Shell", Tactics: []string{tacticPersist}},
	"T1552":     {Name: "Unsecured Credentials", Tactics: []string{tacticCredential}},
	"T1552.001": {Name: "Credentials In Files", Tactics: []string{tacticCredential}},
	"T1557":     {Name: "Adversary-in-the-Middle", Tactics: []string{tacticCredential, tacticCollection}},
	"T1557.001": {Name: "LLMNR/NBT-NS Poisoning and SMB Relay", Tactics: []string{tacticCredential, tacticCollection}},
	"T1590":     {Name: "Gather Victim Network Information", Tactics: []string{tacticRecon}},
	"T1592":     {Name: "Gather Victim Host Information", Tactics: []string{tacticRecon}},
	"T1600":     {Name: "Weaken Encryption", Tactics: []string{tacticEvasion}},
}

func init() {
	// Fill in the id and the canonical ATT&CK URL once, so the table above
	// stays readable and the two can never drift apart.
	for id, t := range catalogue {
		t.ID = id
		t.URL = attackURL(id)
		catalogue[id] = t
	}
}

// attackURL builds the technique's page on attack.mitre.org. A sub-technique
// like T1078.001 lives under its parent: /techniques/T1078/001/.
func attackURL(id string) string {
	if parent, sub, ok := strings.Cut(id, "."); ok {
		return fmt.Sprintf("https://attack.mitre.org/techniques/%s/%s/", parent, sub)
	}
	return fmt.Sprintf("https://attack.mitre.org/techniques/%s/", id)
}

// Lookup returns a technique from the catalogue.
func Lookup(id string) (Technique, bool) {
	t, ok := catalogue[id]
	return t, ok
}

// Catalogue reports how many techniques this build can map to, which the API
// exposes so a client can tell a small mapping table from a missing one.
func Catalogue() int { return len(catalogue) }
