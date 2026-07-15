package nessus

import "time"

// isoFromUnix formats a Unix epoch (seconds) as an ISO-8601 UTC string.
func isoFromUnix(sec int64) string {
	return time.Unix(sec, 0).UTC().Format("2006-01-02T15:04:05Z")
}
