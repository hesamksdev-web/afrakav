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
}

// Host is a single scanned host — the primary search unit, modelled after a
// Shodan host record.
type Host struct {
	IP          string   `json:"ip"`
	Hostnames   []string `json:"hostnames"`
	Domains     []string `json:"domains"`
	Org         string   `json:"org"`
	ISP         string   `json:"isp"`
	ASN         string   `json:"asn"`
	OS          string   `json:"os"`
	Country     string   `json:"country"`
	CountryCode string   `json:"countryCode"`
	City        string   `json:"city"`
	Region      string   `json:"region"`
	LastScan    string   `json:"lastScan"`
	Tags        []string `json:"tags"`
	Ports       []Port   `json:"ports"`
	Vulns       []Vuln   `json:"vulns"`
}
