package nessus

import (
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Store is a thread-safe in-memory collection of hosts keyed by IP. The most
// recent upload for a given IP wins.
type Store struct {
	mu     sync.RWMutex
	byIP   map[string]Host
	source string // filename of the last uploaded scan
}

// NewStore returns an empty store.
func NewStore() *Store {
	return &Store{byIP: map[string]Host{}}
}

// Replace clears the store and loads the given hosts (used on a fresh upload).
func (s *Store) Replace(hosts []Host, source string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byIP = make(map[string]Host, len(hosts))
	for _, h := range hosts {
		s.byIP[h.IP] = h
	}
	s.source = source
}

// Merge adds/updates hosts without clearing existing ones.
func (s *Store) Merge(hosts []Host, source string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, h := range hosts {
		s.byIP[h.IP] = h
	}
	s.source = source
}

// Source returns the filename of the most recent upload.
func (s *Store) Source() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.source
}

// All returns every host, sorted by descending critical-vulnerability count.
func (s *Store) All() []Host {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Host, 0, len(s.byIP))
	for _, h := range s.byIP {
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool {
		ci, cj := countSev(out[i], SeverityCritical), countSev(out[j], SeverityCritical)
		if ci != cj {
			return ci > cj
		}
		return out[i].IP < out[j].IP
	})
	return out
}

// Get returns a single host by exact IP.
func (s *Store) Get(ip string) (Host, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	h, ok := s.byIP[ip]
	return h, ok
}

// Search filters hosts using the Shodan-style query grammar:
//
//	port:445  tag:rdp  vuln:CVE-2021-44228  cve:...  product:jenkins  os:windows
//
// A bare term matches IP, hostname, domain, OS, org, tag, port, service,
// product, CVE, or plugin name (case-insensitive substring).
func (s *Store) Search(q string) []Host {
	return SearchHosts(s.All(), q)
}

// SearchHosts filters an arbitrary host slice with the Shodan-style query
// grammar. It is the shared implementation used by both the in-memory Store and
// the database-backed handlers (which pass a single customer's hosts).
func SearchHosts(hosts []Host, q string) []Host {
	q = strings.TrimSpace(strings.ToLower(q))
	if q == "" {
		return hosts
	}
	out := make([]Host, 0)
	for _, h := range hosts {
		if matches(h, q) {
			out = append(out, h)
		}
	}
	return out
}

func matches(h Host, q string) bool {
	if key, val, ok := splitFilter(q); ok {
		switch key {
		case "port":
			n, _ := strconv.Atoi(val)
			for _, p := range h.Ports {
				if p.Port == n {
					return true
				}
			}
			return false
		case "tag":
			for _, t := range h.Tags {
				if strings.ToLower(t) == val {
					return true
				}
			}
			return false
		case "vuln", "cve":
			for _, v := range h.Vulns {
				if strings.Contains(strings.ToLower(v.CVE), val) {
					return true
				}
			}
			return false
		case "product":
			for _, p := range h.Ports {
				if strings.Contains(strings.ToLower(p.Product), val) {
					return true
				}
			}
			return false
		case "os":
			return strings.Contains(strings.ToLower(h.OS), val)
		}
	}

	if strings.Contains(strings.ToLower(h.IP), q) ||
		strings.Contains(strings.ToLower(h.OS), q) ||
		strings.Contains(strings.ToLower(h.Org), q) {
		return true
	}
	for _, n := range h.Hostnames {
		if strings.Contains(strings.ToLower(n), q) {
			return true
		}
	}
	for _, d := range h.Domains {
		if strings.Contains(strings.ToLower(d), q) {
			return true
		}
	}
	for _, t := range h.Tags {
		if strings.Contains(strings.ToLower(t), q) {
			return true
		}
	}
	for _, p := range h.Ports {
		if strconv.Itoa(p.Port) == q ||
			strings.Contains(strings.ToLower(p.Service), q) ||
			strings.Contains(strings.ToLower(p.Product), q) {
			return true
		}
	}
	for _, v := range h.Vulns {
		if strings.Contains(strings.ToLower(v.CVE), q) ||
			strings.Contains(strings.ToLower(v.Name), q) {
			return true
		}
	}
	return false
}

func splitFilter(q string) (key, val string, ok bool) {
	i := strings.Index(q, ":")
	if i <= 0 {
		return "", "", false
	}
	return q[:i], strings.TrimSpace(q[i+1:]), true
}

func countSev(h Host, s Severity) int {
	n := 0
	for _, v := range h.Vulns {
		if v.Severity == s {
			n++
		}
	}
	return n
}

// Stats is the dashboard summary payload.
type Stats struct {
	Hosts      int            `json:"hosts"`
	OpenPorts  int            `json:"openPorts"`
	TotalCVEs  int            `json:"totalCVEs"`
	Source     string         `json:"source"`
	BySeverity map[string]int `json:"bySeverity"`
}

// Stats computes aggregate counts across all hosts.
func (s *Store) Stats() Stats {
	return ComputeStats(s.All(), s.Source())
}

// ComputeStats aggregates dashboard counts across a host slice. Shared by the
// Store and the database-backed handlers.
func ComputeStats(hosts []Host, source string) Stats {
	out := Stats{
		Hosts:      len(hosts),
		Source:     source,
		BySeverity: map[string]int{},
	}
	seenCVE := map[string]bool{}
	for _, h := range hosts {
		out.OpenPorts += len(h.Ports)
		for _, v := range h.Vulns {
			out.BySeverity[string(v.Severity)]++
			if v.CVE != "" && v.CVE != "N/A" {
				seenCVE[v.CVE] = true
			}
		}
	}
	out.TotalCVEs = len(seenCVE)
	return out
}
