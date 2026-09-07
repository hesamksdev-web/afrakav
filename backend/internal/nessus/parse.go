package nessus

import (
	"encoding/xml"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

// ── Raw XML shape (Nessus v2 / NessusClientData_v2) ─────────────────────────

type xmlClientData struct {
	XMLName xml.Name  `xml:"NessusClientData_v2"`
	Report  xmlReport `xml:"Report"`
}

type xmlReport struct {
	Name  string          `xml:"name,attr"`
	Hosts []xmlReportHost `xml:"ReportHost"`
}

type xmlReportHost struct {
	Name       string          `xml:"name,attr"`
	Properties []xmlTag        `xml:"HostProperties>tag"`
	Items      []xmlReportItem `xml:"ReportItem"`
}

type xmlTag struct {
	Name  string `xml:"name,attr"`
	Value string `xml:",chardata"`
}

type xmlReportItem struct {
	Port         int    `xml:"port,attr"`
	SvcName      string `xml:"svc_name,attr"`
	Protocol     string `xml:"protocol,attr"`
	Severity     int    `xml:"severity,attr"`
	PluginID     string `xml:"pluginID,attr"`
	PluginName   string `xml:"pluginName,attr"`
	PluginFamily string `xml:"pluginFamily,attr"`

	Description   string `xml:"description"`
	Solution      string `xml:"solution"`
	CVSSBaseScore string `xml:"cvss_base_score"`
	CVSS3Score    string `xml:"cvss3_base_score"`
	CVE           string `xml:"cve"`
	SeeAlso       string `xml:"see_also"`
	PluginOutput  string `xml:"plugin_output"`
	SvcProduct    string `xml:"product"`

	ExploitAvailable   string `xml:"exploit_available"`
	ExploitedByMalware string `xml:"exploited_by_malware"`
	ExploitabilityEase string `xml:"exploitability_ease"`
	MetasploitOK       string `xml:"exploit_framework_metasploit"`
	MetasploitName     string `xml:"metasploit_name"`
	CanvasOK           string `xml:"exploit_framework_canvas"`
	CanvasPackage      string `xml:"canvas_package"`
	CoreOK             string `xml:"exploit_framework_core"`
	D2ElliotOK         string `xml:"exploit_framework_d2_elliot"`
}

// Parse reads a Nessus v2 XML document and returns the hosts it describes.
func Parse(r io.Reader) ([]Host, error) {
	var data xmlClientData
	dec := xml.NewDecoder(r)
	dec.Strict = false
	dec.CharsetReader = func(_ string, input io.Reader) (io.Reader, error) { return input, nil }
	if err := dec.Decode(&data); err != nil {
		return nil, fmt.Errorf("decode nessus xml: %w", err)
	}
	if len(data.Report.Hosts) == 0 {
		return nil, fmt.Errorf("no ReportHost entries found — is this a valid .nessus file?")
	}

	hosts := make([]Host, 0, len(data.Report.Hosts))
	for _, rh := range data.Report.Hosts {
		hosts = append(hosts, convertHost(rh))
	}
	return hosts, nil
}

func convertHost(rh xmlReportHost) Host {
	props := map[string]string{}
	for _, t := range rh.Properties {
		props[t.Name] = strings.TrimSpace(t.Value)
	}

	ip := firstNonEmpty(props["host-ip"], rh.Name)

	host := Host{
		IP:        ip,
		Org:       firstNonEmpty(props["host-fqdn"], "—"),
		OS:        firstNonEmpty(props["operating-system"], "Unknown"),
		LastScan:  normalizeTime(firstNonEmpty(props["HOST_END_TIMESTAMP"], props["HOST_END"])),
		Hostnames: []string{},
		Domains:   []string{},
		Tags:      []string{},
		Ports:     []Port{},
		Vulns:     []Vuln{},
	}

	// Hostnames / domains.
	seenName := map[string]bool{}
	for _, key := range []string{"host-fqdn", "netbios-name", "host-rdns"} {
		if v := props[key]; v != "" && !seenName[strings.ToLower(v)] {
			seenName[strings.ToLower(v)] = true
			host.Hostnames = append(host.Hostnames, v)
			if i := strings.Index(v, "."); i >= 0 {
				addUnique(&host.Domains, strings.ToLower(v[i+1:]))
			}
		}
	}

	// Ports and vulns from ReportItems.
	portByNum := map[int]*Port{}
	tags := map[string]bool{}
	for _, it := range rh.Items {
		// Service / port record (any item with a real port + service name).
		if it.Port > 0 && it.SvcName != "" && it.SvcName != "general" {
			proto := it.Protocol
			if proto == "" {
				proto = "tcp"
			}
			if _, ok := portByNum[it.Port]; !ok {
				p := Port{
					Port:    it.Port,
					Proto:   proto,
					Service: it.SvcName,
					Product: firstNonEmpty(it.SvcProduct, it.PluginName),
					Banner:  strings.TrimSpace(it.PluginOutput),
				}
				portByNum[it.Port] = &p
			} else if b := strings.TrimSpace(it.PluginOutput); b != "" && portByNum[it.Port].Banner == "" {
				portByNum[it.Port].Banner = b
			}
		}

		// Vulnerability finding (severity > 0 = Low..Critical).
		if it.Severity > 0 {
			host.Vulns = append(host.Vulns, Vuln{
				CVE:         firstNonEmpty(firstCVE(it.CVE), "N/A"),
				PluginID:    it.PluginID,
				Name:        it.PluginName,
				Severity:    severityForLevel(it.Severity),
				CVSS:        parseFloat(firstNonEmpty(it.CVSS3Score, it.CVSSBaseScore)),
				Family:      it.PluginFamily,
				Description: collapse(it.Description),
				Solution:    collapse(it.Solution),
				SeeAlso:     safeURL(firstLine(it.SeeAlso)),

				ExploitAvailable:   isTrue(it.ExploitAvailable),
				ExploitedByMalware: isTrue(it.ExploitedByMalware),
				ExploitEase:        exploitEase(it.ExploitabilityEase),
				ExploitFrameworks:  exploitFrameworks(it),
			})
		}

		// Derive tags from service names / families for the facet UI.
		if it.SvcName != "" && it.SvcName != "general" {
			tags[it.SvcName] = true
		}
	}

	for _, p := range portByNum {
		host.Ports = append(host.Ports, *p)
	}
	sort.Slice(host.Ports, func(i, j int) bool { return host.Ports[i].Port < host.Ports[j].Port })

	sort.Slice(host.Vulns, func(i, j int) bool {
		return sevRank(host.Vulns[i].Severity) > sevRank(host.Vulns[j].Severity)
	})

	for t := range tags {
		host.Tags = append(host.Tags, t)
	}
	sort.Strings(host.Tags)
	if len(host.Tags) > 12 {
		host.Tags = host.Tags[:12]
	}

	return host
}

// ── helpers ─────────────────────────────────────────────────────────────────

func sevRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func addUnique(list *[]string, v string) {
	for _, e := range *list {
		if e == v {
			return
		}
	}
	*list = append(*list, v)
}

func parseFloat(s string) float64 {
	f, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return f
}

// firstCVE returns the first CVE when the field holds several (Nessus can emit
// multiple <cve> elements which the decoder concatenates).
func firstCVE(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == '\n' || r == ' ' || r == ',' }) {
		if strings.HasPrefix(strings.ToUpper(f), "CVE-") {
			return strings.ToUpper(f)
		}
	}
	return ""
}

// isTrue reads the "true"/"false" strings Nessus writes into boolean tags.
func isTrue(s string) bool {
	return strings.EqualFold(strings.TrimSpace(s), "true")
}

// exploitEase normalises Nessus's exploitability_ease phrasing to one of three
// labels the UI knows how to render.
func exploitEase(s string) string {
	// Order matters: "No known exploits are available" contains "are available",
	// so the negative phrasings have to be tested first.
	switch v := strings.ToLower(strings.TrimSpace(s)); {
	case v == "":
		return ""
	case strings.Contains(v, "no exploit is required"):
		return "no-exploit-needed"
	case strings.Contains(v, "no known exploit"):
		return "none-known"
	case strings.Contains(v, "available"):
		return "public-exploit"
	default:
		return "difficult"
	}
}

// exploitFrameworks lists the offensive toolkits that ship a module for this
// finding — the clearest signal that it is weaponised, not just theoretical.
func exploitFrameworks(it xmlReportItem) []string {
	var out []string
	if isTrue(it.MetasploitOK) {
		name := "Metasploit"
		if n := strings.TrimSpace(it.MetasploitName); n != "" {
			name += ": " + n
		}
		out = append(out, name)
	}
	if isTrue(it.CanvasOK) {
		name := "Canvas"
		if n := strings.TrimSpace(it.CanvasPackage); n != "" {
			name += ": " + n
		}
		out = append(out, name)
	}
	if isTrue(it.CoreOK) {
		out = append(out, "Core Impact")
	}
	if isTrue(it.D2ElliotOK) {
		out = append(out, "D2 Elliot")
	}
	return out
}

// safeURL keeps only plain http(s) links. A .nessus file comes from outside the
// platform and its see_also value is rendered straight into an href, so a
// "javascript:" URL there would run in the viewer's session on one click.
func safeURL(s string) string {
	lower := strings.ToLower(strings.TrimSpace(s))
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return strings.TrimSpace(s)
	}
	return ""
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\n\r"); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}

// collapse trims and normalizes internal whitespace runs of description/solution
// text (Nessus wraps them with hard newlines).
func collapse(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// normalizeTime converts a Unix timestamp string, or passes through a date
// string, producing an ISO-8601 UTC string when possible.
func normalizeTime(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if ts, err := strconv.ParseInt(s, 10, 64); err == nil {
		return isoFromUnix(ts)
	}
	return s
}
