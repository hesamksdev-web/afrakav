package showcase

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/afranet/afrashodan/internal/nessus"
)

func realisticScan() []nessus.Host {
	return []nessus.Host{
		{
			IP:        "203.0.113.42",
			Hostnames: []string{"mail01.corp.acme-bank.local"},
			Domains:   []string{"acme-bank.local"},
			Org:       "Acme Bank",
			OS:        "Ubuntu 22.04 LTS",
			Tags:      []string{"smtp", "ssh"},
			Ports: []nessus.Port{
				{Port: 25, Proto: "tcp", Service: "smtp", Product: "Postfix",
					Banner: "220 mail01.corp.acme-bank.local ESMTP Postfix"},
				{Port: 22, Proto: "tcp", Service: "ssh", Product: "OpenSSH",
					Banner: "SSH-2.0-OpenSSH_8.9p1 acme-bank"},
			},
			Vulns: []nessus.Vuln{
				{CVE: "CVE-2022-3602", Name: "OpenSSL Buffer Overflow", Severity: nessus.SeverityCritical,
					CVSS: 9.6, Description: "blah", Solution: "patch", ExploitAvailable: true},
			},
		},
		{
			IP:        "203.0.113.77",
			Hostnames: []string{"vpn.acme-bank.local"},
			Org:       "Acme Bank",
			OS:        "ArubaOS-CX",
			Ports:     []nessus.Port{{Port: 443, Proto: "tcp", Service: "https", Product: "nginx", Banner: "CN=acme-bank.local"}},
			Vulns: []nessus.Vuln{
				{CVE: "N/A", Name: "SSL Certificate Cannot Be Trusted", Severity: nessus.SeverityMedium, CVSS: 6.5},
			},
		},
	}
}

func TestMaskIP(t *testing.T) {
	cases := []struct {
		ip     string
		octets int
		want   string
	}{
		{"203.0.113.42", 1, "203.0.113.×"},
		{"203.0.113.42", 2, "203.0.×.×"},
		{"203.0.113.42", 3, "203.×.×.×"},
		{"203.0.113.42", 0, "203.0.113.×"}, // clamped up to 1
		{"203.0.113.42", 9, "203.×.×.×"},   // clamped down to 3
		{"2001:db8::1", 2, "×"},            // not a dotted quad
		{"not-an-ip", 2, "×"},
	}
	for _, c := range cases {
		if got := MaskIP(c.ip, c.octets); got != c.want {
			t.Errorf("MaskIP(%q, %d) = %q, want %q", c.ip, c.octets, got, c.want)
		}
	}
}

// The whole point of the package: nothing that names a customer may survive.
func TestAnonymiseDropsEverythingIdentifying(t *testing.T) {
	s := Anonymise(realisticScan(), 2, time.Now())

	blob, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	serialised := strings.ToLower(string(blob))

	// Whatever the shape of the output, none of these may appear anywhere in
	// it — including inside a banner, which is the easiest one to forget.
	for _, secret := range []string{
		"acme-bank", "mail01", "vpn.acme", "acme bank",
		"corp.acme-bank.local", "esmtp", "cn=",
		"203.0.113.42", "203.0.113.77", "203.0.113",
	} {
		if strings.Contains(serialised, strings.ToLower(secret)) {
			t.Errorf("showcase leaked %q", secret)
		}
	}

	if problems := Leak(s); len(problems) > 0 {
		t.Errorf("Leak reported: %v", problems)
	}
}

func TestAnonymiseKeepsWhatMakesItInteresting(t *testing.T) {
	s := Anonymise(realisticScan(), 2, time.Now())

	if len(s.Hosts) != 2 {
		t.Fatalf("kept %d hosts, want 2", len(s.Hosts))
	}
	// Worst host first, so the sample leads with something worth seeing.
	if s.Hosts[0].Vulns[0].Severity != nessus.SeverityCritical {
		t.Errorf("sample is not risk-ordered: first host is %+v", s.Hosts[0].Vulns)
	}
	if s.Hosts[0].OS != "Ubuntu 22.04 LTS" {
		t.Errorf("OS was dropped: %q", s.Hosts[0].OS)
	}
	if len(s.Hosts[0].Ports) != 2 || s.Hosts[0].Ports[0].Service != "smtp" {
		t.Errorf("ports were mangled: %+v", s.Hosts[0].Ports)
	}
	// "N/A" is a parser placeholder, not a CVE; it should not reach the page.
	for _, h := range s.Hosts {
		for _, v := range h.Vulns {
			if v.CVE == "N/A" {
				t.Error(`a vuln kept the "N/A" CVE placeholder`)
			}
		}
	}
}

func TestStatsCoverTheWholeScanNotJustTheSample(t *testing.T) {
	s := Anonymise(realisticScan(), 2, time.Now())

	if s.Stats.Hosts != 2 || s.Stats.OpenPorts != 3 || s.Stats.Findings != 2 {
		t.Errorf("stats = %+v", s.Stats)
	}
	if s.Stats.CVEs != 1 { // "N/A" must not be counted as a CVE
		t.Errorf("CVEs = %d, want 1", s.Stats.CVEs)
	}
	if s.Stats.BySeverity["Critical"] != 1 || s.Stats.BySeverity["Medium"] != 1 {
		t.Errorf("bySeverity = %v", s.Stats.BySeverity)
	}
	if len(s.Stats.Services) == 0 {
		t.Error("no service breakdown produced")
	}
}

func TestSampleIsCapped(t *testing.T) {
	big := make([]nessus.Host, MaxHosts+25)
	for i := range big {
		big[i] = nessus.Host{IP: "10.0.0.1", OS: "Linux"}
	}
	s := Anonymise(big, 2, time.Now())

	if len(s.Hosts) != MaxHosts {
		t.Errorf("kept %d hosts, want the cap of %d", len(s.Hosts), MaxHosts)
	}
	// The stats still describe everything that was scanned.
	if s.Stats.Hosts != MaxHosts+25 {
		t.Errorf("stats.Hosts = %d, want %d", s.Stats.Hosts, MaxHosts+25)
	}
}

func TestEmptyScanIsSafe(t *testing.T) {
	s := Anonymise(nil, 2, time.Now())
	if len(s.Hosts) != 0 || s.Stats.Hosts != 0 {
		t.Errorf("empty scan produced %+v", s)
	}
	// Empty slices, not nil, so the JSON carries [] rather than null.
	blob, _ := json.Marshal(s)
	if strings.Contains(string(blob), "null") {
		t.Errorf("empty showcase serialised nulls: %s", blob)
	}
}
