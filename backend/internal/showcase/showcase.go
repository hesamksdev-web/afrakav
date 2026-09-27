// Package showcase turns a real Nessus scan into something safe to publish on
// a public landing page.
//
// The anonymisation happens once, at ingest — the stored showcase record holds
// only the redacted form, and the raw scan is never persisted for this purpose.
// Redacting at render time instead would mean one careless endpoint, or one
// future field added to the model, quietly exposing a customer's estate.
//
// Masking the IP is the obvious half. The half that actually leaks is
// everything around it: a hostname like mail01.corp.acme-bank.local, a service
// banner carrying a certificate's common name, the organisation string Nessus
// copies from the scan. Those are dropped outright rather than masked, because
// a partially masked hostname is still a hostname.
package showcase

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/afranet/afrashodan/internal/nessus"
)

// MaxHosts caps what a showcase can hold. The landing page shows a sample, not
// an estate, and a bounded payload keeps both the exposure and the public
// response small.
const MaxHosts = 60

// Port is a service on a showcased host. No banner: that is where hostnames
// and certificate names hide.
type Port struct {
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	Service string `json:"service"`
	Product string `json:"product"`
}

// Vuln is a finding, reduced to what a landing page can show. Descriptions and
// remediation text are plugin boilerplate and are left out to keep the public
// payload small.
type Vuln struct {
	CVE      string          `json:"cve,omitempty"`
	Name     string          `json:"name"`
	Severity nessus.Severity `json:"severity"`
	CVSS     float64         `json:"cvss"`
}

// Host is one anonymised host.
type Host struct {
	IP    string   `json:"ip"` // already masked; never a full address
	OS    string   `json:"os"`
	Tags  []string `json:"tags"`
	Ports []Port   `json:"ports"`
	Vulns []Vuln   `json:"vulns"`
}

// Stats summarises the whole scan, including the hosts that were not kept.
type Stats struct {
	Hosts      int            `json:"hosts"`
	OpenPorts  int            `json:"openPorts"`
	Findings   int            `json:"findings"`
	CVEs       int            `json:"cves"`
	BySeverity map[string]int `json:"bySeverity"`
	Services   []ServiceCount `json:"services"`
}

// ServiceCount is one row of the "what is exposed out there" breakdown.
type ServiceCount struct {
	Port    int    `json:"port"`
	Service string `json:"service"`
	Hosts   int    `json:"hosts"`
}

// Showcase is the published, public-safe document.
type Showcase struct {
	PublishedAt time.Time `json:"publishedAt"`
	MaskOctets  int       `json:"maskOctets"`
	Hosts       []Host    `json:"hosts"`
	Stats       Stats     `json:"stats"`
}

// MaskIP hides the last `octets` parts of an IPv4 address.
//
// Two is the safe default. Masking only the last octet leaves the /24 intact,
// and a /24 of public address space is attributable to its owner through a
// routing registry — which defeats the point for exactly the customers whose
// addresses are public.
func MaskIP(ip string, octets int) string {
	if octets < 1 {
		octets = 1
	}
	if octets > 3 {
		octets = 3
	}

	parsed := net.ParseIP(strings.TrimSpace(ip))
	if v4 := parsed.To4(); v4 != nil {
		parts := strings.Split(v4.String(), ".")
		for i := len(parts) - octets; i < len(parts); i++ {
			parts[i] = "×"
		}
		return strings.Join(parts, ".")
	}

	// Not a dotted quad (IPv6, or something the scanner wrote oddly). Nothing
	// here can be masked reliably, so it is replaced wholesale.
	return "×"
}

// Anonymise redacts a parsed scan into a publishable showcase.
func Anonymise(hosts []nessus.Host, maskOctets int, now time.Time) Showcase {
	out := Showcase{
		PublishedAt: now.UTC(),
		MaskOctets:  maskOctets,
		Hosts:       []Host{},
		Stats:       Stats{BySeverity: map[string]int{}, Services: []ServiceCount{}},
	}

	cves := map[string]bool{}
	type svc struct {
		service string
		hosts   map[string]bool
	}
	services := map[int]*svc{}

	// Worst hosts first: a showcase that leads with empty hosts says nothing.
	ranked := make([]nessus.Host, len(hosts))
	copy(ranked, hosts)
	sort.SliceStable(ranked, func(i, j int) bool {
		return riskScore(ranked[i]) > riskScore(ranked[j])
	})

	for _, h := range hosts {
		// Stats describe the whole scan, not just the sample that is kept.
		out.Stats.Hosts++
		out.Stats.OpenPorts += len(h.Ports)
		for _, p := range h.Ports {
			s := services[p.Port]
			if s == nil {
				s = &svc{service: p.Service, hosts: map[string]bool{}}
				services[p.Port] = s
			}
			if s.service == "" {
				s.service = p.Service
			}
			s.hosts[h.IP] = true
		}
		for _, v := range h.Vulns {
			out.Stats.Findings++
			out.Stats.BySeverity[string(v.Severity)]++
			if v.CVE != "" && v.CVE != "N/A" {
				cves[v.CVE] = true
			}
		}
	}
	out.Stats.CVEs = len(cves)

	for port, s := range services {
		out.Stats.Services = append(out.Stats.Services, ServiceCount{
			Port: port, Service: s.service, Hosts: len(s.hosts),
		})
	}
	sort.Slice(out.Stats.Services, func(i, j int) bool {
		if out.Stats.Services[i].Hosts != out.Stats.Services[j].Hosts {
			return out.Stats.Services[i].Hosts > out.Stats.Services[j].Hosts
		}
		return out.Stats.Services[i].Port < out.Stats.Services[j].Port
	})
	if len(out.Stats.Services) > 10 {
		out.Stats.Services = out.Stats.Services[:10]
	}

	for _, h := range ranked {
		if len(out.Hosts) >= MaxHosts {
			break
		}
		out.Hosts = append(out.Hosts, anonymiseHost(h, maskOctets))
	}
	return out
}

// anonymiseHost keeps only fields that describe a machine, never an owner.
func anonymiseHost(h nessus.Host, maskOctets int) Host {
	out := Host{
		IP: MaskIP(h.IP, maskOctets),
		OS: h.OS,
		// Hostnames, Domains and Org are deliberately absent: each one names
		// the customer directly.
		Tags:  append([]string{}, h.Tags...),
		Ports: []Port{},
		Vulns: []Vuln{},
	}

	for _, p := range h.Ports {
		out.Ports = append(out.Ports, Port{
			Port:    p.Port,
			Proto:   p.Proto,
			Service: p.Service,
			Product: p.Product,
			// Banner dropped: it carries certificate names, mail server
			// greetings and hostnames straight from the target.
		})
	}

	for _, v := range h.Vulns {
		cve := v.CVE
		if cve == "N/A" {
			cve = ""
		}
		out.Vulns = append(out.Vulns, Vuln{
			CVE:      cve,
			Name:     v.Name,
			Severity: v.Severity,
			CVSS:     v.CVSS,
		})
	}
	return out
}

// riskScore orders the sample so the landing page leads with hosts that show
// something worth seeing.
func riskScore(h nessus.Host) int {
	score := 0
	for _, v := range h.Vulns {
		switch v.Severity {
		case nessus.SeverityCritical:
			score += 100
		case nessus.SeverityHigh:
			score += 40
		case nessus.SeverityMedium:
			score += 10
		case nessus.SeverityLow:
			score += 3
		}
		if v.ExploitAvailable {
			score += 50
		}
	}
	return score
}

// Leak reports any field that would identify a customer if it were published.
// It exists so the anonymiser can be checked against its own promise rather
// than trusted: a test runs it over a redacted showcase and expects silence.
func Leak(s Showcase) []string {
	problems := []string{}
	for _, h := range s.Hosts {
		if !strings.Contains(h.IP, "×") {
			problems = append(problems, fmt.Sprintf("host %q carries an unmasked address", h.IP))
		}
		for _, p := range h.Ports {
			if strings.Contains(strings.ToLower(p.Product), "://") {
				problems = append(problems, fmt.Sprintf("port %d product looks like a URL", p.Port))
			}
		}
	}
	return problems
}
