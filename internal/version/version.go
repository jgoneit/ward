// Package version exposes Ward build identity. Release builds may replace
// Version, Commit, and Date with -ldflags.
package version

var (
	Version = "0.1.0-dev.0"
	Commit  = "unknown"
	Date    = "unknown"
)

func String() string {
	return "ward " + Version
}
