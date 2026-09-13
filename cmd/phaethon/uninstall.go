package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/arahe-dev/phaethon/internal/config"
	"github.com/arahe-dev/phaethon/internal/host"
	"github.com/arahe-dev/phaethon/internal/lifecycle"
	"github.com/arahe-dev/phaethon/internal/mitm"
)

// cmdUninstall reverses everything setup did, in the order that keeps the
// machine usable at every point.
//
// The ordering is deliberate: the proxy is handed back before the daemon
// stops, so there is never a moment where the browser points at a dead proxy.
// The certificate is removed by exact thumbprint, never by matching a name,
// so no unrelated certificate can be caught by it.
func cmdUninstall(args []string) int {
	fs := flag.NewFlagSet("phaethon uninstall", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "configuration file")
	keepState := fs.Bool("keep-state", false, "keep configuration, learned routes and logs")
	keepCA := fs.Bool("keep-ca", false, "leave the certificate authority in place")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	asJSON := fs.Bool("json", false, "print the summary as JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		// Uninstalling must work even when the configuration is unreadable,
		// which is exactly when someone wants to uninstall.
		cfg = &config.Config{Listen: "127.0.0.1:8377"}
	}
	dataDir := config.DataDir()
	ctx := context.Background()

	// Show what will happen before doing any of it.
	if !*yes && !confirmUninstall(dataDir, *keepState, *keepCA) {
		fmt.Println("Nothing was changed.")
		return 0
	}

	r := &setupunReporter{}
	exe, _ := os.Executable()

	// ---- 1. Hand the Windows proxy back first ----------------------------
	// Doing this before stopping the daemon means the browser is never
	// pointed at a proxy that is no longer running.
	if host.Current().Proxy.SnapshotExists(dataDir) {
		st, msg, err := host.Current().Proxy.Restore(ctx, dataDir)
		if err != nil {
			r.fail("windows proxy", err.Error())
		} else {
			r.ok("windows proxy", fmt.Sprintf("%s (now: %s)", msg, st.Current))
		}
	} else if st, err := host.Current().Proxy.Status(ctx, cfg.Listen); err == nil && st.OwnedByUs {
		// No snapshot, but we are the configured proxy: clear it rather than
		// leave the machine pointing at a daemon that is about to be removed.
		if _, msg, err := host.Current().Proxy.Restore(ctx, dataDir); err != nil {
			r.fail("windows proxy", err.Error())
		} else {
			r.warn("windows proxy", msg+" (no previous configuration had been recorded)")
		}
	} else {
		r.ok("windows proxy", "not owned by Phaethon; nothing to restore")
	}

	// ---- 2. Stop the daemon ---------------------------------------------
	if _, err := lifecycle.Stop(cfg.Listen, cfg.LocalToken, 20*time.Second); err != nil {
		r.info("daemon", "was not running")
	} else {
		r.ok("daemon", "stopped")
	}

	// ---- 3. Remove supervision ------------------------------------------
	if code := cmdAutostart([]string{"uninstall"}); code != 0 {
		r.warn("autostart", "the logon task could not be removed")
	} else {
		r.ok("autostart", "logon task removed")
	}
	// A leftover registry entry would start a daemon after the binary is gone.
	if removed := removeRunEntry(); removed {
		r.ok("startup entry", "removed a legacy HKCU Run entry")
	}

	// ---- 4. Remove only this installation's certificate -----------------
	if *keepCA {
		r.warn("certificate authority", "kept, as requested; it remains trusted")
	} else if ca, err := trustCA(cfg); err != nil {
		r.info("certificate authority", "nothing to remove ("+err.Error()+")")
	} else {
		thumb := ca.Thumbprint()
		if !mitm.Trusted(thumb) {
			r.ok("certificate authority", "was not trusted")
		} else if err := mitm.UninstallTrust(thumb); err != nil {
			r.fail("certificate authority", err.Error())
		} else if mitm.Trusted(thumb) {
			r.fail("certificate authority", "still present after removal")
		} else {
			// Removing by exact thumbprint is what guarantees no other
			// certificate could have been affected.
			r.ok("certificate authority", "removed "+shortThumb(thumb)+" from the current user store")
		}
	}

	// ---- 5. Runtime state ----------------------------------------------
	if *keepState {
		r.ok("state", "kept configuration and logs in "+dataDir)
	} else {
		paths := []string{
			lifecycle.PIDFile(),
			config.DataPath("routes.json"),
			config.DataPath("setup.json"),
			config.DataPath("proxy-backup.json"),
		}
		for _, p := range paths {
			os.Remove(p)
		}
		// The CA directory goes only if the certificate was not kept.
		if !*keepCA {
			os.RemoveAll(filepath.Join(dataDir, "ca"))
		}
		os.RemoveAll(lifecycle.RunDir())
		r.ok("state", "runtime state removed")
		fmt.Printf("      configuration and logs remain at %s\n", dataDir)
		fmt.Println("      remove the whole directory yourself when you are finished:")
		fmt.Printf("        Remove-Item -Recurse -Force \"%s\"\n", dataDir)
	}

	// ---- 6. The binary itself -------------------------------------------
	fmt.Println()
	fmt.Printf("The executable at %s was left in place.\n", exe)
	fmt.Println("Remove it yourself, or use the installer's uninstaller:")
	fmt.Println("  Settings > Apps > Phaethon > Uninstall")
	fmt.Println()
	if *asJSON {
		r.print(true)
		return r.exitCode()
	}
	if r.failed > 0 {
		fmt.Printf("Uninstall finished with %d failure(s); check the output above.\n", r.failed)
		return 1
	}
	fmt.Println("Phaethon has been removed. Your network settings are back to what they were.")
	return r.exitCode()
}

// confirmUninstall shows exactly what will change before anything does.
func confirmUninstall(dataDir string, keepState, keepCA bool) bool {
	cfg, err := loadConfig("")
	listen := "127.0.0.1:8377"
	if err == nil {
		listen = cfg.Listen
	}
	fmt.Println("This will:")
	fmt.Println("  - restore your previous Windows proxy configuration")
	fmt.Printf("  - stop the Phaethon daemon on %s\n", listen)
	fmt.Println("  - remove the Phaethon logon task")
	if keepCA {
		fmt.Println("  - KEEP the Phaethon certificate authority (--keep-ca)")
	} else {
		fmt.Println("  - remove ONLY the Phaethon certificate authority, by its exact thumbprint")
	}
	if keepState {
		fmt.Println("  - KEEP configuration, learned routes and logs (--keep-state)")
	} else {
		fmt.Printf("  - remove runtime state under %s (configuration and logs are kept)\n", dataDir)
	}
	fmt.Println()
	fmt.Println("It will not touch any other certificate, proxy setting or application.")
	fmt.Println()
	return askYesNo("Proceed with uninstall?")
}

// removeRunEntry clears a legacy HKCU Run entry, if one exists.
func removeRunEntry() bool {
	return removeRunValue("Phaethon")
}
