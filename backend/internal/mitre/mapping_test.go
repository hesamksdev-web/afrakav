package mitre

import (
	"strings"
	"testing"

	"github.com/afranet/afrashodan/internal/nessus"
)

func techniqueIDs(ms []Match) []string {
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, m.ID)
	}
	return out
}

func has(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

// Every technique a rule or a CWE names must exist in the catalogue,
// otherwise the mapping silently drops it at runtime.
func TestEveryMappedTechniqueExists(t *testing.T) {
	for cwe, ids := range byCWE {
		for _, id := range ids {
			if _, ok := catalogue[id]; !ok {
				t.Errorf("%s maps to %s, which is not in the catalogue", cwe, id)
			}
		}
	}
	for _, r := range rules {
		for _, id := range r.techniques {
			if _, ok := catalogue[id]; !ok {
				t.Errorf("rule %q maps to %s, which is not in the catalogue", r.reason, id)
			}
		}
	}
}

func TestTechniqueURLs(t *testing.T) {
	if got := catalogue["T1190"].URL; got != "https://attack.mitre.org/techniques/T1190/" {
		t.Errorf("T1190 URL = %q", got)
	}
	// A sub-technique lives under its parent.
	if got := catalogue["T1078.001"].URL; got != "https://attack.mitre.org/techniques/T1078/001/" {
		t.Errorf("T1078.001 URL = %q", got)
	}
}

// The whole reason the rule path exists: findings with no CVE and no CWE are
// the majority of a real estate, and they must still map.
func TestRulesMapFindingsWithoutCVEorCWE(t *testing.T) {
	cases := map[string]string{
		"SNMP Agent Default Community Name (public)":    "T1078.001",
		"SSL Certificate Cannot Be Trusted":             "T1557",
		"HTTP TRACE / TRACK Methods Allowed":            "T1190",
		"SMB Signing not required":                      "T1557.001",
		"SSL Medium Strength Cipher Suites Supported":   "T1600",
		"ICMP Timestamp Request Remote Date Disclosure": "T1592",
	}
	for name, want := range cases {
		v := nessus.Vuln{Name: name, CVE: "N/A", Severity: nessus.SeverityMedium, Family: "General"}
		got := techniqueIDs(Map([]nessus.Vuln{v}).Techniques)
		if !has(got, want) {
			t.Errorf("%q mapped to %v, want it to include %s", name, got, want)
		}
	}
}

func TestCWEPathIsLabelledAsWeakness(t *testing.T) {
	v := nessus.Vuln{
		Name: "Some Overflow", CVE: "CVE-2022-1234", Severity: nessus.SeverityCritical,
		CWE: []string{"CWE-787"},
	}
	res := Map([]nessus.Vuln{v})
	if len(res.Techniques) == 0 {
		t.Fatal("a CWE-787 finding mapped to nothing")
	}
	for _, m := range res.Techniques {
		if len(m.Sources) == 0 || m.Sources[0] != SourceWeakness {
			t.Errorf("%s sources = %v, want weakness first", m.ID, m.Sources)
		}
		if len(m.Findings) != 1 || m.Findings[0].CVE != "CVE-2022-1234" {
			t.Errorf("%s did not carry its finding: %+v", m.ID, m.Findings)
		}
	}
}

// A technique reached by both paths reports both, weakness first.
func TestBothSourcesAreReported(t *testing.T) {
	v := nessus.Vuln{
		Name: "Remote Code Execution in Thing", CVE: "CVE-2021-1", Severity: nessus.SeverityCritical,
		CWE: []string{"CWE-787"}, // -> T1203, T1210 ; the rule also gives T1210
	}
	for _, m := range Map([]nessus.Vuln{v}).Techniques {
		if m.ID != "T1210" {
			continue
		}
		if len(m.Sources) != 2 || m.Sources[0] != SourceWeakness || m.Sources[1] != SourceRule {
			t.Errorf("T1210 sources = %v, want [weakness rule]", m.Sources)
		}
		return
	}
	t.Fatal("T1210 was not produced")
}

// Unmapped findings are counted, never quietly dropped.
func TestUnmappedFindingsAreCounted(t *testing.T) {
	vulns := []nessus.Vuln{
		{Name: "SNMP Agent Default Community Name (public)", Severity: nessus.SeverityHigh},
		{Name: "Something With No Signal Whatsoever", Severity: nessus.SeverityLow},
	}
	res := Map(vulns)
	if res.TotalFindings != 2 || res.MappedFindings != 1 || res.UnmappedFindings != 1 {
		t.Errorf("counts = total %d mapped %d unmapped %d, want 2/1/1",
			res.TotalFindings, res.MappedFindings, res.UnmappedFindings)
	}
}

func TestEmptyHostMapsToNothing(t *testing.T) {
	res := Map(nil)
	if len(res.Techniques) != 0 || res.TotalFindings != 0 || res.UnmappedFindings != 0 {
		t.Errorf("an empty host produced %+v", res)
	}
}

func TestMapEstateCountsHostsNotFindings(t *testing.T) {
	snmp := nessus.Vuln{Name: "SNMP Agent Default Community Name (public)", Severity: nessus.SeverityHigh}
	hosts := []nessus.Host{
		{IP: "10.0.0.1", Vulns: []nessus.Vuln{snmp}},
		{IP: "10.0.0.2", Vulns: []nessus.Vuln{snmp}},
		{IP: "10.0.0.3", Vulns: nil}, // clean host
	}
	e := MapEstate(hosts)
	if e.Hosts != 3 || e.AffectedHosts != 2 {
		t.Errorf("hosts = %d, affected = %d, want 3 and 2", e.Hosts, e.AffectedHosts)
	}
	for _, t1 := range e.Techniques {
		if t1.ID == "T1078.001" {
			if t1.Hosts != 2 {
				t.Errorf("T1078.001 hosts = %d, want 2", t1.Hosts)
			}
			return
		}
	}
	t.Fatal("T1078.001 missing from the estate mapping")
}

func TestNavigatorLayerShape(t *testing.T) {
	hosts := []nessus.Host{{IP: "10.0.0.1", Vulns: []nessus.Vuln{
		{Name: "SSL Certificate Cannot Be Trusted", Severity: nessus.SeverityMedium},
	}}}
	layer := NavigatorLayerFor("test", MapEstate(hosts))

	if layer.Domain != "enterprise-attack" || layer.Versions.Layer != "4.5" {
		t.Errorf("layer header = %+v", layer)
	}
	if len(layer.Techniques) == 0 {
		t.Fatal("layer carries no techniques")
	}
	for _, tech := range layer.Techniques {
		if tech.Score < 1 || !tech.Enabled {
			t.Errorf("technique %+v", tech)
		}
		// A rule-only mapping must say so, so nobody reads it as MITRE's.
		if !strings.Contains(tech.Comment, "inferred") {
			t.Errorf("rule-only technique %s lost its caveat: %q", tech.TechniqueID, tech.Comment)
		}
	}
	if layer.Gradient.MaxValue < 1 {
		t.Errorf("gradient max = %d", layer.Gradient.MaxValue)
	}
}
