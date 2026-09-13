//go:build windows

package main

import (
	"os/exec"
	"strings"
)

// chromiumProcess is one browser process, with the command line that proves
// how it was launched.
type chromiumProcess struct {
	PID         int
	CommandLine string
}

// chromiumProcesses lists Chromium-family processes with their command lines.
//
// Command lines are the only trustworthy way to know whether a browser is
// actually proxied: a shortcut being clicked proves nothing, and Chromium may
// have handed the URL to an existing process.
func chromiumProcesses() ([]chromiumProcess, error) {
	// The CIM query is the supported way to read command lines without
	// elevation; Win32_Process exposes CommandLine for the caller's own
	// processes.
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		"Get-CimInstance Win32_Process -Filter \"Name='chrome.exe' or Name='msedge.exe' or Name='helium.exe'\" | "+
			"Where-Object { $_.ExecutablePath -match 'Helium|Chrome|Edge' } | "+
			"ForEach-Object { \"$($_.ProcessId)`t$($_.CommandLine)\" }").Output()
	if err != nil {
		return nil, err
	}
	var procs []chromiumProcess
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		pidText, cmdline, found := strings.Cut(line, "\t")
		if !found {
			continue
		}
		pid := 0
		for _, r := range strings.TrimSpace(pidText) {
			if r < '0' || r > '9' {
				pid = 0
				break
			}
			pid = pid*10 + int(r-'0')
		}
		if pid == 0 {
			continue
		}
		procs = append(procs, chromiumProcess{PID: pid, CommandLine: cmdline})
	}
	return procs, nil
}
