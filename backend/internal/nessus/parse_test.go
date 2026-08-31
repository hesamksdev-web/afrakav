package nessus

import (
	"os"
	"testing"
)

func loadSample(t *testing.T) []Host {
	t.Helper()
	f, err := os.Open("../../data/sample.nessus")
	if err != nil {
		t.Fatalf("open sample: %v", err)
	}
	defer f.Close()
	hosts, err := Parse(f)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return hosts
}

func TestParseSample(t *testing.T) {
	hosts := loadSample(t)
	if len(hosts) != 2 {
		t.Fatalf("want 2 hosts, got %d", len(hosts))
	}

	byIP := map[string]Host{}
	for _, h := range hosts {
		byIP[h.IP] = h
	}

	web, ok := byIP["192.168.10.5"]
	if !ok {
		t.Fatal("missing host 192.168.10.5")
	}
	if got := len(web.Ports); got != 3 {
		t.Errorf("web ports: want 3, got %d", got)
	}
	// severity 0 item (ssh) must NOT become a vuln; the two >0 items must.
	if got := len(web.Vulns); got != 2 {
		t.Errorf("web vulns: want 2, got %d", got)
	}
	// Highest-severity finding sorts first.
	if web.Vulns[0].Severity != SeverityCritical {
		t.Errorf("web first vuln severity: want Critical, got %s", web.Vulns[0].Severity)
	}
	if web.Vulns[0].CVE != "CVE-2022-3602" {
		t.Errorf("web first vuln cve: got %s", web.Vulns[0].CVE)
	}
	if web.OS != "Ubuntu 22.04 LTS (Jammy Jellyfish)" {
		t.Errorf("web os: got %q", web.OS)
	}
}

func TestStoreSearch(t *testing.T) {
	s := NewStore()
	s.Replace(loadSample(t), "sample.nessus")

	cases := []struct {
		q    string
		want int
	}{
		{"port:445", 1},
		{"port:22", 1},
		{"vuln:CVE-2019-0708", 1},
		{"os:windows", 1},
		{"os:linux", 0}, // OS string says "Ubuntu ... Jammy", not "linux"
		{"nonexistent", 0},
		{"", 2},
	}
	for _, c := range cases {
		if got := len(s.Search(c.q)); got != c.want {
			t.Errorf("Search(%q): want %d, got %d", c.q, c.want, got)
		}
	}
}

func TestStats(t *testing.T) {
	s := NewStore()
	s.Replace(loadSample(t), "sample.nessus")
	st := s.Stats()
	if st.Hosts != 2 {
		t.Errorf("stats hosts: want 2, got %d", st.Hosts)
	}
	// CVE-2022-3602, CVE-2019-0708, CVE-2017-0144 = 3 unique CVEs.
	if st.TotalCVEs != 3 {
		t.Errorf("stats totalCVEs: want 3, got %d", st.TotalCVEs)
	}
	if st.BySeverity["Critical"] != 3 {
		t.Errorf("stats critical: want 3, got %d", st.BySeverity["Critical"])
	}
}

func TestSafeURLRejectsScriptSchemes(t *testing.T) {
	for _, in := range []string{
		"javascript:alert(document.cookie)",
		"JavaScript:alert(1)",
		"data:text/html,<script>alert(1)</script>",
		"vbscript:msgbox(1)",
		"  javascript:alert(1)",
	} {
		if got := safeURL(in); got != "" {
			t.Errorf("safeURL(%q) = %q, want empty", in, got)
		}
	}
	for _, in := range []string{
		"https://www.tenable.com/plugins/nessus/12345",
		"http://example.com/advisory",
	} {
		if got := safeURL(in); got != in {
			t.Errorf("safeURL(%q) = %q, want it kept", in, got)
		}
	}
}
