package nessus

import "testing"

func hostFixture() []Host {
	return []Host{
		{
			IP:    "10.20.30.11",
			OS:    "Windows Server 2019",
			Ports: []Port{{Port: 445, Proto: "tcp", Service: "cifs"}},
			Vulns: []Vuln{{
				CVE: "CVE-2017-0144", Severity: SeverityCritical,
				ExploitAvailable: true, ExploitedByMalware: true,
				ExploitFrameworks: []string{"Metasploit: MS17-010 EternalBlue"},
			}},
		},
		{
			IP:    "10.20.31.5",
			OS:    "Ubuntu 22.04",
			Ports: []Port{{Port: 22, Proto: "tcp", Service: "ssh"}},
			Vulns: []Vuln{{CVE: "CVE-2023-0001", Severity: SeverityMedium}},
		},
	}
}

func TestExploitAndSubnetFilters(t *testing.T) {
	hosts := hostFixture()

	cases := map[string][]string{
		"has:exploit":       {"10.20.30.11"},
		"has:malware":       {"10.20.30.11"},
		"has:critical":      {"10.20.30.11"},
		"exploit:false":     {"10.20.31.5"},
		"subnet:10.20.31":   {"10.20.31.5"},
		"subnet:10.20.30.":  {"10.20.30.11"},
		"net:10.20.3":       {}, // must not match 10.20.30.* or 10.20.31.*
		"has:somethingelse": {},
	}

	for query, want := range cases {
		got := SearchHosts(hosts, query)
		if len(got) != len(want) {
			t.Errorf("%q returned %d hosts, want %d", query, len(got), len(want))
			continue
		}
		for i, ip := range want {
			if got[i].IP != ip {
				t.Errorf("%q result %d = %s, want %s", query, i, got[i].IP, ip)
			}
		}
	}
}

func TestStatsCountsExploitableFindings(t *testing.T) {
	s := ComputeStats(hostFixture(), "test.nessus")
	if s.ExploitableFindings != 1 {
		t.Errorf("ExploitableFindings = %d, want 1", s.ExploitableFindings)
	}
	if s.ExploitableHosts != 1 {
		t.Errorf("ExploitableHosts = %d, want 1", s.ExploitableHosts)
	}
	if s.MalwareFindings != 1 {
		t.Errorf("MalwareFindings = %d, want 1", s.MalwareFindings)
	}
}

func TestExploitEaseLabels(t *testing.T) {
	cases := map[string]string{
		"":                                      "",
		"Exploits are available":                "public-exploit",
		"No exploit is required":                "no-exploit-needed",
		"No known exploits are available":       "none-known",
		"Something the plugin has not said yet": "difficult",
	}
	for in, want := range cases {
		if got := exploitEase(in); got != want {
			t.Errorf("exploitEase(%q) = %q, want %q", in, got, want)
		}
	}
}
