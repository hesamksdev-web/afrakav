// Package nessus provides parsing of Tenable Nessus (.nessus) v2 XML scan
// files into the flat host/port/vulnerability shape the Afrashodan frontend
// consumes. JSON tags intentionally use camelCase to match the TypeScript
// interfaces in src/app/App.tsx.
package nessus

// Severity is the human-readable Nessus severity label.
type Severity string

const (
	SeverityCritical Severity = "Critical"
	SeverityHigh     Severity = "High"
	SeverityMedium   Severity = "Medium"
	SeverityLow      Severity = "Low"
	SeverityInfo     Severity = "Info"
)

// severityForLevel maps the numeric Nessus severity (0-4) to a label.
func severityForLevel(level int) Severity {
	switch level {
	case 4:
		return SeverityCritical
	case 3:
		return SeverityHigh
	case 2:
		return SeverityMedium
	case 1:
		return SeverityLow
	default:
		return SeverityInfo
	}
}

// Port is a single open port / discovered service on a host.
type Port struct {
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	Service string `json:"service"`
	Product string `json:"product"`
	Banner  string `json:"banner"`
}

// Vuln is a single vulnerability finding.
type Vuln struct {
	CVE         string   `json:"cve"`
	PluginID    string   `json:"pluginId"`
	Name        string   `json:"name"`
	Severity    Severity `json:"severity"`
	CVSS        float64  `json:"cvss"`
	Family      string   `json:"family"`
	Description string   `json:"description"`
	Solution    string   `json:"solution"`
	SeeAlso     string   `json:"seeAlso,omitempty"`

	// Exploit intelligence straight from the Nessus plugin. A finding with a
	// public exploit is the one to fix first, whatever its CVSS says.
	ExploitAvailable   bool     `json:"exploitAvailable"`
	ExploitedByMalware bool     `json:"exploitedByMalware"`
	ExploitEase        string   `json:"exploitEase,omitempty"`
	ExploitFrameworks  []string `json:"exploitFrameworks,omitempty"`
}

// Host is a single scanned host — the primary search unit, modelled after a
// Shodan host record.
type Host struct {
	// A .nessus file records no location, ISP or ASN, so the model does not
	// carry those fields: the UI describes a host by its subnet instead.
	IP        string   `json:"ip"`
	Hostnames []string `json:"hostnames"`
	Domains   []string `json:"domains"`
	Org       string   `json:"org"`
	OS        string   `json:"os"`
	LastScan  string   `json:"lastScan"`
	Tags      []string `json:"tags"`
	Ports     []Port   `json:"ports"`
	Vulns     []Vuln   `json:"vulns"`
}
