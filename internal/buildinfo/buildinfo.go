// Package buildinfo carries ldflags-injected build metadata so every
// internal package (panel client, machine orchestrator) can report the
// running agent version without importing main.
package buildinfo

// Set by -ldflags -X at build time (see Makefile).
var (
	Version   = "dev"
	BuildTime = "unknown"
	Commit    = "unknown"
)
