//go:build !windows

package main

import "errors"

// chromiumProcess is one browser process, with the command line that proves
// how it was launched.
type chromiumProcess struct {
	PID         int
	CommandLine string
}

// chromiumProcesses is not implemented away from the platform this daemon
// targets, rather than pretending to inspect processes it cannot read.
func chromiumProcesses() ([]chromiumProcess, error) {
	return nil, errors.New("browser process inspection is only implemented for Windows")
}
