package mitre

import (
	"sort"
	"strings"

	"github.com/afranet/afrashodan/internal/nessus"
)

// Source says where a mapping came from, so a caller can tell an external
// weakness mapping from our own rule.
type Source string

const (
	SourceWeakness Source = "weakness"
	SourceRule     Source = "rule"
)

// byCWE maps a weakness class to the techniques an attacker exercises when
// they abuse it. Keys are normalised "CWE-n" strings, matching the parser.
var byCWE = map[string][]string{
	"CWE-20":  {"T1190"},              // improper input validation
	"CWE-22":  {"T1190", "T1083"},     // path traversal
	"CWE-78":  {"T1190", "T1059"},     // OS command injection
	"CWE-79":  {"T1190"},              // cross-site scripting
	"CWE-89":  {"T1190"},              // SQL injection
	"CWE-94":  {"T1190", "T1059"},     // code injection
	"CWE-119": {"T1203", "T1210"},     // buffer overflow
	"CWE-120": {"T1203", "T1210"},     // classic buffer overflow
	"CWE-125": {"T1203", "T1210"},     // out-of-bounds read
	"CWE-200": {"T1592"},              // information exposure
	"CWE-259": {"T1078.001"},          // hard-coded password
	"CWE-269": {"T1068"},              // improper privilege management
	"CWE-284": {"T1078"},              // improper access control
	"CWE-287": {"T1078"},              // improper authentication
	"CWE-295": {"T1557"},              // improper certificate validation
	"CWE-306": {"T1078"},              // missing authentication
	"CWE-311": {"T1040", "T1557"},     // missing encryption
	"CWE-319": {"T1040", "T1557"},     // cleartext transmission
	"CWE-326": {"T1600"},              // inadequate encryption strength
	"CWE-327": {"T1600"},              // broken or risky crypto
	"CWE-352": {"T1190"},              // cross-site request forgery
	"CWE-400": {"T1499"},              // uncontrolled resource consumption
	"CWE-416": {"T1203", "T1210"},     // use after free
	"CWE-434": {"T1505.003"},          // unrestricted file upload
	"CWE-502": {"T1190"},              // deserialisation of untrusted data
	"CWE-522": {"T1552"},              // insufficiently protected credentials
	"CWE-787": {"T1203", "T1210"},     // out-of-bounds write
	"CWE-798": {"T1078.001", "T1552"}, // hard-coded credentials
}

// rule matches a finding by its name or its plugin family — either trigger is
// enough, because Nessus spells families differently across versions and a
// clearly named finding should not go unmapped over that. `not` vetoes the
// match outright.
type rule struct {
	reason     string
	anyName    []string
	anyFamily  []string
	not        []string
	techniques []string
}

// rules are ordered only for readability — a finding may match several, and
// every match contributes.
var rules = []rule{
	{
		reason:     "اعتبارنامهٔ پیش‌فرض یا بدون رمز",
		anyName:    []string{"default community", "default password", "default credential", "default account", "blank password", "no password", "guessable", "anonymous"},
		techniques: []string{"T1078.001"},
	},
	{
		reason:     "رمز عبور ضعیف یا قابل حدس",
		anyName:    []string{"weak password", "password policy", "brute force", "password guessing"},
		techniques: []string{"T1110"},
	},
	{
		reason:     "انتقال بدون رمزنگاری",
		anyName:    []string{"cleartext", "clear text", "unencrypted", "plaintext", "telnet"},
		techniques: []string{"T1040", "T1557"},
	},
	{
		reason:     "گواهی نامعتبر یا غیرقابل اعتماد",
		anyName:    []string{"certificate cannot be trusted", "self-signed", "self signed", "certificate expired", "certificate is expired", "hostname mismatch", "certificate chain"},
		techniques: []string{"T1557"},
	},
	{
		reason:     "رمزنگاری ضعیف یا منسوخ",
		anyName:    []string{"sslv2", "sslv3", "ssl version 2", "ssl version 3", "weak cipher", "medium strength cipher", "rc4", "weak hashing", "sha-1", "tlsv1.0", "tlsv1.1", "tls version 1.0", "tls version 1.1", "poodle", "sweet32", "logjam", "freak", "drown", "weak encryption"},
		techniques: []string{"T1600", "T1040"},
	},
	{
		reason:     "امضای SMB الزامی نیست",
		anyName:    []string{"smb signing"},
		techniques: []string{"T1557.001", "T1021.002"},
	},
	{
		reason:     "سرویس دسکتاپ راه دور",
		anyName:    []string{"remote desktop", "terminal services", "bluekeep"},
		techniques: []string{"T1021.001"},
	},
	{
		reason:     "ضعف در پیکربندی SSH",
		anyName:    []string{"ssh weak", "ssh server cbc", "ssh protocol version 1", "terrapin", "ssh weak algorithms"},
		techniques: []string{"T1021.004", "T1600"},
	},
	{
		reason:     "سرویس SNMP قابل پرس‌وجو",
		anyFamily:  []string{"snmp"},
		anyName:    []string{"snmp"},
		techniques: []string{"T1046", "T1592"},
	},
	{
		reason:     "افشای اطلاعات میزبان",
		anyName:    []string{"information disclosure", "icmp timestamp", "banner", "version disclosure", "netbios", "system information"},
		not:        []string{"remote code execution"},
		techniques: []string{"T1592"},
	},
	{
		reason:     "افشای ساختار شبکه",
		anyName:    []string{"traceroute", "network information", "routing information"},
		techniques: []string{"T1590"},
	},
	{
		reason:     "شمارش حساب‌های کاربری",
		anyName:    []string{"user enumeration", "username enumeration", "account enumeration"},
		techniques: []string{"T1087"},
	},
	{
		reason:     "پیکربندی نادرست وب‌سرور",
		anyName:    []string{"trace / track", "trace/track", "http trace", "trace method", "track method", "webdav", "http methods allowed", "directory listing", "browsable web"},
		techniques: []string{"T1190"},
	},
	{
		reason:     "فهرست‌برداری از مسیرها",
		anyName:    []string{"directory listing", "browsable web", "directory indexing"},
		techniques: []string{"T1083"},
	},
	{
		reason:     "اجرای کد از راه دور",
		anyName:    []string{"remote code execution", "arbitrary code", "code execution", "command execution", "command injection"},
		techniques: []string{"T1210"},
	},
	{
		reason:     "خرابی حافظه",
		anyName:    []string{"buffer overflow", "out-of-bounds", "use-after-free", "use after free", "memory corruption", "integer overflow"},
		techniques: []string{"T1203", "T1210"},
	},
	{
		reason:     "ارتقای سطح دسترسی",
		anyName:    []string{"privilege escalation", "elevation of privilege"},
		techniques: []string{"T1068"},
	},
	{
		reason:     "از کار انداختن سرویس",
		anyName:    []string{"denial of service"},
		techniques: []string{"T1499"},
	},
	{
		reason:     "وصلهٔ امنیتی نصب‌نشده",
		anyName:    []string{"security update", "missing patch", "patch is missing", "security patch"},
		anyFamily:  []string{"microsoft bulletins"},
		techniques: []string{"T1210", "T1068"},
	},
	{
		reason:     "نرم‌افزار پشتیبانی‌نشده",
		anyName:    []string{"unsupported", "end of life", "no longer supported", "obsolete version"},
		techniques: []string{"T1190"},
	},
	{
		reason:     "افشای اعتبارنامه",
		anyName:    []string{"password disclosure", "credentials disclosure", "hardcoded", "credentials in"},
		techniques: []string{"T1552", "T1552.001"},
	},
	{
		reason:     "بارگذاری فایل بدون محدودیت",
		anyName:    []string{"file upload", "web shell", "webshell"},
		techniques: []string{"T1505.003"},
	},
	{
		reason:     "سرویس دسترسی از بیرون",
		anyName:    []string{"openvpn", "citrix netscaler", "remote access service", "vpn server"},
		techniques: []string{"T1133"},
	},
}

// FindingRef identifies the finding that produced a technique, so the UI can
// show the evidence instead of an unexplained badge.
type FindingRef struct {
	PluginID string `json:"pluginId"`
	Name     string `json:"name"`
	CVE      string `json:"cve,omitempty"`
	Severity string `json:"severity"`
}

// Match is one technique, plus why it is here.
type Match struct {
	Technique
	Sources  []Source     `json:"sources"`
	Reasons  []string     `json:"reasons"`
	Findings []FindingRef `json:"findings"`
}

// Result is the mapping for a single host.
type Result struct {
	Techniques       []Match `json:"techniques"`
	TotalFindings    int     `json:"totalFindings"`
	MappedFindings   int     `json:"mappedFindings"`
	UnmappedFindings int     `json:"unmappedFindings"`
}

// hit is one technique attributed to one finding.
type hit struct {
	technique string
	source    Source
	reason    string
}

// hitsFor runs both mapping paths over a single finding.
func hitsFor(v nessus.Vuln) []hit {
	out := []hit{}

	for _, cwe := range v.CWE {
		for _, id := range byCWE[cwe] {
			out = append(out, hit{technique: id, source: SourceWeakness, reason: cwe})
		}
	}

	name := strings.ToLower(v.Name)
	family := strings.ToLower(v.Family)
	for _, r := range rules {
		matched := containsAny(name, r.anyName) || containsAny(family, r.anyFamily)
		if !matched {
			continue
		}
		if len(r.not) > 0 && containsAny(name, r.not) {
			continue
		}
		for _, id := range r.techniques {
			out = append(out, hit{technique: id, source: SourceRule, reason: r.reason})
		}
	}
	return out
}

func containsAny(haystack string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(haystack, n) {
			return true
		}
	}
	return false
}

// Map turns one host's findings into the techniques they enable. Findings that
// map to nothing are counted rather than hidden: a technique list means very
// little without knowing how much of the risk it failed to cover.
func Map(vulns []nessus.Vuln) Result {
	res := Result{Techniques: []Match{}, TotalFindings: len(vulns)}

	type agg struct {
		sources  map[Source]bool
		reasons  map[string]bool
		findings []FindingRef
		seen     map[string]bool
	}
	byTechnique := map[string]*agg{}

	for _, v := range vulns {
		hits := hitsFor(v)
		if len(hits) == 0 {
			continue
		}
		res.MappedFindings++

		ref := FindingRef{
			PluginID: v.PluginID,
			Name:     v.Name,
			Severity: string(v.Severity),
		}
		if v.CVE != "" && v.CVE != "N/A" {
			ref.CVE = v.CVE
		}

		for _, h := range hits {
			if _, known := catalogue[h.technique]; !known {
				continue // a rule naming a technique this build does not carry
			}
			a := byTechnique[h.technique]
			if a == nil {
				a = &agg{sources: map[Source]bool{}, reasons: map[string]bool{}, seen: map[string]bool{}}
				byTechnique[h.technique] = a
			}
			a.sources[h.source] = true
			a.reasons[h.reason] = true
			key := v.PluginID + "|" + v.Name
			if !a.seen[key] {
				a.seen[key] = true
				a.findings = append(a.findings, ref)
			}
		}
	}
	res.UnmappedFindings = res.TotalFindings - res.MappedFindings

	for id, a := range byTechnique {
		m := Match{Technique: catalogue[id], Findings: a.findings}
		// weakness first: an external mapping outranks our own rule.
		if a.sources[SourceWeakness] {
			m.Sources = append(m.Sources, SourceWeakness)
		}
		if a.sources[SourceRule] {
			m.Sources = append(m.Sources, SourceRule)
		}
		for r := range a.reasons {
			m.Reasons = append(m.Reasons, r)
		}
		sort.Strings(m.Reasons)
		res.Techniques = append(res.Techniques, m)
	}

	sort.Slice(res.Techniques, func(i, j int) bool {
		if len(res.Techniques[i].Findings) != len(res.Techniques[j].Findings) {
			return len(res.Techniques[i].Findings) > len(res.Techniques[j].Findings)
		}
		return res.Techniques[i].ID < res.Techniques[j].ID
	})
	return res
}

// EstateMatch is a technique seen across the whole estate.
type EstateMatch struct {
	Technique
	Sources  []Source `json:"sources"`
	Hosts    int      `json:"hosts"`
	Findings int      `json:"findings"`
}

// EstateResult is the mapping across every host a customer owns.
type EstateResult struct {
	Techniques       []EstateMatch `json:"techniques"`
	Hosts            int           `json:"hosts"`
	AffectedHosts    int           `json:"affectedHosts"`
	TotalFindings    int           `json:"totalFindings"`
	MappedFindings   int           `json:"mappedFindings"`
	UnmappedFindings int           `json:"unmappedFindings"`
	CatalogueSize    int           `json:"catalogueSize"`
}

// MapEstate aggregates the per-host mapping, counting how many hosts each
// technique touches — the number a defender prioritises on.
func MapEstate(hosts []nessus.Host) EstateResult {
	res := EstateResult{
		Techniques:    []EstateMatch{},
		Hosts:         len(hosts),
		CatalogueSize: Catalogue(),
	}

	type agg struct {
		sources  map[Source]bool
		hosts    int
		findings int
	}
	byTechnique := map[string]*agg{}

	for _, h := range hosts {
		r := Map(h.Vulns)
		res.TotalFindings += r.TotalFindings
		res.MappedFindings += r.MappedFindings
		res.UnmappedFindings += r.UnmappedFindings
		if len(r.Techniques) > 0 {
			res.AffectedHosts++
		}
		for _, m := range r.Techniques {
			a := byTechnique[m.ID]
			if a == nil {
				a = &agg{sources: map[Source]bool{}}
				byTechnique[m.ID] = a
			}
			a.hosts++
			a.findings += len(m.Findings)
			for _, s := range m.Sources {
				a.sources[s] = true
			}
		}
	}

	for id, a := range byTechnique {
		m := EstateMatch{Technique: catalogue[id], Hosts: a.hosts, Findings: a.findings}
		if a.sources[SourceWeakness] {
			m.Sources = append(m.Sources, SourceWeakness)
		}
		if a.sources[SourceRule] {
			m.Sources = append(m.Sources, SourceRule)
		}
		res.Techniques = append(res.Techniques, m)
	}

	sort.Slice(res.Techniques, func(i, j int) bool {
		if res.Techniques[i].Hosts != res.Techniques[j].Hosts {
			return res.Techniques[i].Hosts > res.Techniques[j].Hosts
		}
		return res.Techniques[i].ID < res.Techniques[j].ID
	})
	return res
}
