//go:build windows

package host

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/arahe-dev/phaethon/internal/mitm"
	"github.com/arahe-dev/phaethon/internal/winproxy"
)

// Current returns the Windows host adapter.
func Current() Host {
	return Host{
		Proxy:   windowsProxy{},
		Trust:   windowsTrust{},
		Startup: windowsStartup{},
		Paths:   windowsPaths{},
		OS:      runtime.GOOS,
		Arch:    runtime.GOARCH,
	}
}

// ---- paths -----------------------------------------------------------------

// windowsPaths keeps state under ProgramData, which is machine-wide and
// already the location a previous release used; the configuration itself is
// still restricted to its owner.
type windowsPaths struct{}

func (windowsPaths) root() string {
	if d := os.Getenv("PHAETHON_DATA_DIR"); d != "" {
		return d
	}
	if pd := os.Getenv("ProgramData"); pd != "" {
		return filepath.Join(pd, "Phaethon")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".phaethon")
}

func (p windowsPaths) DataDir() string   { return p.root() }
func (p windowsPaths) ConfigDir() string { return p.root() }
func (p windowsPaths) LogDir() string    { return filepath.Join(p.root(), "logs") }
func (p windowsPaths) RunDir() string    { return filepath.Join(p.root(), "run") }

// ---- proxy -----------------------------------------------------------------

// windowsProxy delegates to the WinINET implementation, which owns the setting
// transactionally and restores it exactly. The adapter exists so the rest of
// the product never mentions WinINET.
type windowsProxy struct{}

func (windowsProxy) Capability() Capability { return Supported }
func (windowsProxy) Manager() string        { return "WinINET (current user)" }

func (windowsProxy) Status(ctx context.Context, listen string) (ProxyStatus, error) {
	st, err := winproxy.Describe(windowsPaths{}.root(), listen)
	if err != nil {
		return ProxyStatus{Capability: Supported, Manager: "WinINET (current user)"}, err
	}
	return ProxyStatus{
		Capability:    Supported,
		Manager:       "WinINET (current user)",
		Enabled:       st.Enabled,
		OwnedByUs:     st.PointsAtUs,
		Current:       st.Current,
		PreviousSaved: st.Saved,
		Previous:      st.PreviousProxy,
		Listen:        listen,
	}, nil
}

func (windowsProxy) Enable(ctx context.Context, cfg ProxyConfig, dataDir string) (ProxyStatus, error) {
	if _, err := winproxy.Enable(dataDir, cfg.HTTP, "phaethon proxy enable"); err != nil {
		return ProxyStatus{}, err
	}
	return windowsProxy{}.Status(ctx, cfg.HTTP)
}

func (windowsProxy) Restore(ctx context.Context, dataDir string) (ProxyStatus, string, error) {
	st, msg, err := winproxy.Disable(dataDir)
	if err != nil {
		return ProxyStatus{}, "", err
	}
	out, _ := windowsProxy{}.Status(ctx, st.Listen)
	return out, msg, nil
}

// ---- trust -----------------------------------------------------------------

type windowsTrust struct{}

func (windowsTrust) Capability() Capability { return Supported }
func (windowsTrust) Manager() string        { return "Windows current-user root store" }

func (windowsTrust) Install(ctx context.Context, certPath, fingerprint string) error {
	_, err := mitm.InstallTrust(certPath)
	return err
}

func (windowsTrust) Remove(ctx context.Context, fingerprint string) error {
	return mitm.UninstallTrust(fingerprint)
}

func (windowsTrust) Trusted(ctx context.Context, fingerprint string) bool {
	return mitm.Trusted(fingerprint)
}

func (windowsTrust) ManualHint(certPath string) string {
	return "import " + certPath + " into Certificates - Current User > Trusted Root Certification Authorities"
}

// ---- startup ---------------------------------------------------------------

type windowsStartup struct{}

func (windowsStartup) Capability() Capability { return Supported }
func (windowsStartup) Manager() string        { return "Task Scheduler (logon + watchdog)" }

// SnapshotExists reports whether a previous WinINET configuration is retained.
func (windowsProxy) SnapshotExists(dataDir string) bool {
	_, exists, err := winproxy.LoadSnapshot(winproxy.SnapshotPath(dataDir))
	return err == nil && exists
}

// ---- startup (scheduled task) ----------------------------------------------

// watchdogMinutes is how often the idempotent `up` re-runs. Startup and crash
// recovery are the same mechanism, which is why there is only one thing to get
// right, and the interval is minutes rather than seconds so a persistent
// failure cannot become a tight loop.
const watchdogMinutes = 5

// taskName is the scheduled task Phaethon registers.
const taskName = "Phaethon"

// registerScript builds the PowerShell that creates or replaces the task.
//
// Arguments reach the process raw: Task Scheduler is not a shell and does not
// strip quotes, so the config path is double-quoted, which is what Windows
// command-line parsing understands.
func registerScript(exe, cfgPath string) string {
	argument := "up --quiet"
	if cfgPath != "" {
		argument += ` --config "` + cfgPath + `"`
	}
	return `
$ErrorActionPreference = 'Stop'
$exe = '` + strings.ReplaceAll(exe, "'", "''") + `'
$arg = '` + strings.ReplaceAll(argument, "'", "''") + `'
$action  = New-ScheduledTaskAction -Execute $exe -Argument $arg
$logon   = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$watch   = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes ` +
		fmt.Sprint(watchdogMinutes) + `)
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries ` +
		`-StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -Hidden
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive
Register-ScheduledTask -TaskName '` + taskName + `' -Action $action -Trigger @($logon, $watch) ` +
		`-Settings $settings -Principal $principal -Force | Out-Null
`
}

// taskQueryScript reports the registered task as JSON, or nothing.
func taskQueryScript() string {
	return `
$t = Get-ScheduledTask -TaskName '` + taskName + `' -ErrorAction SilentlyContinue
if ($null -eq $t) { return }
$i = Get-ScheduledTaskInfo -TaskName '` + taskName + `' -ErrorAction SilentlyContinue
[pscustomobject]@{
  state      = $t.State.ToString()
  execute    = $t.Actions[0].Execute
  arguments  = $t.Actions[0].Arguments
  last_run   = if ($i) { $i.LastRunTime.ToString('o') } else { '' }
  last_result= if ($i) { $i.LastTaskResult } else { 0 }
} | ConvertTo-Json -Compress
`
}

// runPowerShell runs a script and returns its output.
func runPowerShell(script string) (string, error) {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return string(out), fmt.Errorf("%s", strings.TrimSpace(string(ee.Stderr)))
		}
		return string(out), err
	}
	return string(out), nil
}

func (windowsStartup) Status(ctx context.Context) (StartupStatus, error) {
	st := StartupStatus{Capability: Supported, Manager: "Task Scheduler (logon + watchdog)"}
	out, err := runPowerShell(taskQueryScript())
	trimmed := strings.TrimSpace(out)
	if trimmed == "" || err != nil {
		st.ManualHint = "run: phaethon autostart install"
		return st, nil
	}
	var doc struct {
		State      string `json:"state"`
		Execute    string `json:"execute"`
		Arguments  string `json:"arguments"`
		LastRun    string `json:"last_run"`
		LastResult any    `json:"last_result"`
	}
	if json.Unmarshal([]byte(firstJSONLine(trimmed)), &doc) != nil {
		return st, nil
	}
	st.Enabled = true
	st.Detail = doc.State + ": " + doc.Arguments
	st.LastRun = doc.LastRun
	if state := taskResultState(fmt.Sprint(doc.LastResult)); state != "" {
		st.LastError = fmt.Sprintf("the task last exited with %v", doc.LastResult)
	}
	return st, nil
}

func (windowsStartup) Enable(ctx context.Context, exe, configPath string) (StartupStatus, error) {
	if _, err := runPowerShell(registerScript(exe, configPath)); err != nil {
		return StartupStatus{}, fmt.Errorf("register the logon task: %w", err)
	}
	return windowsStartup{}.Status(ctx)
}

func (windowsStartup) Disable(ctx context.Context) error {
	_, err := runPowerShell("Unregister-ScheduledTask -TaskName '" + taskName + "' -Confirm:$false -ErrorAction SilentlyContinue")
	return err
}

// firstJSONLine guards against a profile banner preceding the JSON.
func firstJSONLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(line); strings.HasPrefix(t, "{") {
			return t
		}
	}
	return s
}

// taskResultState classifies a Task Scheduler last-result code. Anything in
// the SCHED_S_* range is informational rather than a failure: the most common,
// 267011, simply means the task has not run yet, which is true of every
// freshly registered installation and must not be reported as a problem.
func taskResultState(raw string) string {
	switch strings.TrimSpace(raw) {
	case "", "0", "<nil>":
		return ""
	}
	if n, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil && n >= 267009 && n <= 267016 {
		return ""
	}
	return checkWarnLocal
}

// checkWarnLocal mirrors the CLI's warn label without importing it.
const checkWarnLocal = "WARN"
