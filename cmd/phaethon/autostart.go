package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/arahe-dev/phaethon/internal/lifecycle"
)

// The autostart task name, and how often the watchdog re-runs the idempotent
// `up`. The same command provides both startup and crash recovery, which is
// the point: there is only one thing to get right.
const (
	autostartTaskName = "Phaethon"
	watchdogInterval  = 5 // minutes
)

// registerScript creates or replaces the logon + watchdog task.
//
// `phaethon up` is idempotent, so running it at logon and every few minutes
// means exactly one daemon exists and a crashed daemon comes back without any
// separate supervisor process. The interval is deliberately minutes, not
// seconds, so a persistent failure cannot become a crash loop.
func registerScript(exe, cfgPath string) string {
	// Arguments reach the process raw: Task Scheduler is not a shell and does
	// not strip quotes. Double quotes are what Windows command-line parsing
	// understands, so anything else (single quotes, for instance) arrives as
	// part of the path and the daemon cannot find its configuration.
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
$watch   = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) ` +
		`-RepetitionInterval (New-TimeSpan -Minutes ` + fmt.Sprint(watchdogInterval) + `)
$settings = New-ScheduledTaskSettingsSet ` +
		`-AllowStartIfOnBatteries -DontStopIfGoingOnBatteries ` +
		`-StartWhenAvailable -MultipleInstances IgnoreNew ` +
		`-ExecutionTimeLimit (New-TimeSpan -Minutes 2) ` +
		`-Hidden
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive
Register-ScheduledTask -TaskName '` + autostartTaskName + `' ` +
		`-Action $action -Trigger @($logon, $watch) -Settings $settings -Principal $principal -Force | Out-Null
`
}

// taskQueryScript reports the registered task as JSON, or nothing.
func taskQueryScript() string {
	return `
$t = Get-ScheduledTask -TaskName '` + autostartTaskName + `' -ErrorAction SilentlyContinue
if ($null -eq $t) { return }
$i = Get-ScheduledTaskInfo -TaskName '` + autostartTaskName + `' -ErrorAction SilentlyContinue
[pscustomobject]@{
  name       = $t.TaskName
  state      = $t.State.ToString()
  execute    = $t.Actions[0].Execute
  arguments  = $t.Actions[0].Arguments
  last_run   = if ($i) { $i.LastRunTime.ToString('o') } else { '' }
  last_result= if ($i) { $i.LastTaskResult } else { 0 }
  next_run   = if ($i) { $i.NextRunTime.ToString('o') } else { '' }
} | ConvertTo-Json -Compress
`
}

// runPowerShell runs a script and returns its standard output.
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

// verifyAutostart proves the task exists, runs the expected command, and that
// the command actually produces a healthy daemon.
func verifyAutostart() (map[string]any, error) {
	out, err := runPowerShell(taskQueryScript())
	trimmed := strings.TrimSpace(out)
	if trimmed == "" {
		return nil, fmt.Errorf("no %q scheduled task is registered", autostartTaskName)
	}
	if err != nil {
		return nil, err
	}
	var info map[string]any
	if err := json.Unmarshal([]byte(firstJSONLine(trimmed)), &info); err != nil {
		return nil, fmt.Errorf("could not read the task definition: %w", err)
	}
	return info, nil
}

// firstJSONLine guards against a profile banner preceding the JSON.
func firstJSONLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "{") {
			return line
		}
	}
	return s
}

// cmdAutostart manages the logon task that keeps exactly one daemon alive.
func cmdAutostart(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "phaethon autostart: install|uninstall|status is required")
		return 2
	}
	flags, _ := splitFlags(args[1:], map[string]bool{"config": true})
	fs := flag.NewFlagSet("phaethon autostart", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "configuration file")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	quiet := fs.Bool("quiet", false, "print nothing on success")
	if err := fs.Parse(flags); err != nil {
		return 2
	}

	switch args[0] {
	case "install", "enable":
		exe, err := os.Executable()
		if err != nil {
			fmt.Fprintln(os.Stderr, "phaethon:", err)
			return 1
		}
		target := configPath(*cfgPath)
		if _, err := runPowerShell(registerScript(exe, target)); err != nil {
			fmt.Fprintln(os.Stderr, "phaethon: register the logon task:", err)
			return 1
		}
		info, err := verifyAutostart()
		if err != nil {
			fmt.Fprintln(os.Stderr, "phaethon: the task was created but could not be verified:", err)
			return 1
		}
		if !strings.Contains(fmt.Sprint(info["arguments"]), "up") {
			fmt.Fprintf(os.Stderr, "phaethon: the task does not run `up`; it would not be idempotent\n")
			return 1
		}
		if *asJSON {
			out, _ := json.Marshal(info)
			fmt.Println(string(out))
			return 0
		}
		if *quiet {
			return 0
		}
		fmt.Printf("installed scheduled task %q\n", autostartTaskName)
		fmt.Printf("  runs      %s %s\n", info["execute"], info["arguments"])
		fmt.Printf("  triggers  at logon, and every %d minutes as a watchdog\n", watchdogInterval)
		fmt.Printf("  log       %s\n", lifecycle.LogFile())
		fmt.Println("Because `up` is idempotent, the watchdog cannot create a second daemon.")
		return 0

	case "uninstall", "disable":
		if _, err := runPowerShell(
			"Unregister-ScheduledTask -TaskName '" + autostartTaskName + "' -Confirm:$false -ErrorAction SilentlyContinue"); err != nil {
			fmt.Fprintln(os.Stderr, "phaethon: remove the logon task:", err)
			return 1
		}
		if !*quiet {
			fmt.Printf("removed scheduled task %q\n", autostartTaskName)
		}
		return 0

	case "status":
		info, err := verifyAutostart()
		if err != nil {
			if *asJSON {
				fmt.Printf("{\"installed\":false,\"error\":%q}\n", err.Error())
				return 1
			}
			fmt.Printf("autostart  not installed (%v)\n", err)
			fmt.Println("           install it with: phaethon autostart install")
			return 1
		}
		// Confirm the whole chain, not just the registration.
		health, herr := lifecycle.Probe(listenOf(*cfgPath), 2*time.Second)
		if *asJSON {
			info["daemon_healthy"] = herr == nil
			out, _ := json.Marshal(info)
			fmt.Println(string(out))
			return 0
		}
		fmt.Printf("autostart  %s (%v)\n", autostartTaskName, info["state"])
		fmt.Printf("  runs     %v %v\n", info["execute"], info["arguments"])
		fmt.Printf("  last run %v (result %v)\n", info["last_run"], info["last_result"])
		fmt.Printf("  next run %v\n", info["next_run"])
		if herr != nil {
			fmt.Printf("  daemon   NOT reachable: %v\n", herr)
			return 1
		}
		fmt.Printf("  daemon   healthy (pid %d, version %s)\n", health.PID, health.Version)
		return 0

	default:
		fmt.Fprintf(os.Stderr, "phaethon autostart: unknown subcommand %q\n", args[0])
		return 2
	}
}

// listenOf resolves the configured listen address, so autostart status can
// check the live daemon rather than only the registration.
func listenOf(cfgPath string) string {
	if cfg, err := loadConfig(cfgPath); err == nil {
		return cfg.Listen
	}
	return "127.0.0.1:8377"
}
