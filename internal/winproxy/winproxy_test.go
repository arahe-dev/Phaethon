//go:build windows

package winproxy

import (
	"os"
	"path/filepath"
	"testing"
)

// Routing detection must understand both the bare and per-scheme forms, since
// which one Windows holds depends on how it was configured.
func TestContainsProxy(t *testing.T) {
	cases := []struct {
		server string
		listen string
		want   bool
	}{
		{"127.0.0.1:8377", "127.0.0.1:8377", true},
		{"http=127.0.0.1:8377;https=127.0.0.1:8377", "127.0.0.1:8377", true},
		{"http=proxy.corp:8080;https=127.0.0.1:8377", "127.0.0.1:8377", true},
		{"proxy.corp:8080", "127.0.0.1:8377", false},
		{"127.0.0.1:9999", "127.0.0.1:8377", false},
		{"", "127.0.0.1:8377", false},
		{"http=127.0.0.1:83770", "127.0.0.1:8377", false},
	}
	for _, c := range cases {
		if got := containsProxy(c.server, c.listen); got != c.want {
			t.Errorf("containsProxy(%q, %q) = %v, want %v", c.server, c.listen, got, c.want)
		}
	}
}

// A PAC URL takes precedence over a static proxy in WinINET, so a
// configuration that still has one must never be reported as routing through
// Phaethon: claiming otherwise is how the browser silently stays unproxied
// while status insists it is fine.
func TestPointsAtRespectsPACPrecedence(t *testing.T) {
	ours := State{ProxyEnable: 1, ProxyServer: "127.0.0.1:8377"}
	if !ours.PointsAt("127.0.0.1:8377") {
		t.Error("a plain configuration pointing at us should report true")
	}
	withPAC := ours
	withPAC.AutoConfigURL = "http://corp/proxy.pac"
	if withPAC.PointsAt("127.0.0.1:8377") {
		t.Error("a PAC URL overrides the static proxy, so this must not report true")
	}
	disabled := State{ProxyEnable: 0, ProxyServer: "127.0.0.1:8377"}
	if disabled.PointsAt("127.0.0.1:8377") {
		t.Error("a disabled proxy does not route anything")
	}
}

// Describe must be readable, since it is what an operator sees.
func TestDescribe(t *testing.T) {
	cases := map[string]State{
		"direct (no proxy configured)": {ProxyEnable: 0},
		"PAC http://corp/p.pac":        {ProxyEnable: 1, AutoConfigURL: "http://corp/p.pac"},
	}
	for want, st := range cases {
		if got := st.Describe(); got != want {
			t.Errorf("Describe() = %q, want %q", got, want)
		}
	}
	withBypass := State{ProxyEnable: 1, ProxyServer: "127.0.0.1:8377", ProxyOverride: Bypass}
	if got := withBypass.Describe(); got == "" || got == "direct (no proxy configured)" {
		t.Errorf("Describe() = %q, want the proxy and its bypass", got)
	}
}

// The snapshot must round-trip exactly, including which values were absent:
// "absent" and "empty" are different states to restore, and getting that wrong
// would leave invented registry values behind.
func TestSnapshotRoundTripPreservesPresence(t *testing.T) {
	dir := t.TempDir()
	path := SnapshotPath(dir)

	original := State{
		ProxyEnable:      0,
		ProxyServer:      "",
		ProxyOverride:    "",
		AutoConfigURL:    "",
		HadProxyEnable:   true, // the value existed and was 0
		HadProxyServer:   false,
		HadProxyOverride: false,
		HadAutoConfigURL: false,
	}
	if err := SaveSnapshot(path, original); err != nil {
		t.Fatal(err)
	}
	got, ok, err := LoadSnapshot(path)
	if err != nil || !ok {
		t.Fatalf("LoadSnapshot = %+v, %v, %v", got, ok, err)
	}
	if got.HadProxyEnable != original.HadProxyEnable ||
		got.HadProxyServer != original.HadProxyServer ||
		got.HadProxyOverride != original.HadProxyOverride ||
		got.HadAutoConfigURL != original.HadAutoConfigURL {
		t.Fatalf("presence flags changed across the round trip:\n got %+v\nwant %+v", got, original)
	}
	if got.ProxyEnable != 0 {
		t.Errorf("ProxyEnable = %d, want 0", got.ProxyEnable)
	}

	// Removing it means Phaethon no longer owns the proxy.
	if err := RemoveSnapshot(path); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := LoadSnapshot(path); ok {
		t.Error("a removed snapshot still loaded")
	}
}

// A missing snapshot is "we do not own the proxy", not an error.
func TestMissingSnapshotIsNotAnError(t *testing.T) {
	_, ok, err := LoadSnapshot(filepath.Join(t.TempDir(), "absent.json"))
	if err != nil {
		t.Fatalf("a missing snapshot should not be an error: %v", err)
	}
	if ok {
		t.Error("a missing snapshot reported as present")
	}
}

// A snapshot from a different schema must be refused rather than misread: a
// wrongly restored proxy is worse than none.
func TestForeignSnapshotIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy-backup.json")
	if err := os.WriteFile(path, []byte(`{"version": 99, "state": {}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := LoadSnapshot(path); err == nil || ok {
		t.Fatalf("ok=%v err=%v, want the foreign snapshot refused", ok, err)
	}
}

// A corrupt snapshot must not be silently treated as a valid one.
func TestCorruptSnapshotIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy-backup.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := LoadSnapshot(path); err == nil || ok {
		t.Fatalf("ok=%v err=%v, want the corrupt snapshot refused", ok, err)
	}
}

// SnapshotPath lives under the daemon's own state directory, so recovery finds
// it by the same path as everything else.
func TestSnapshotPath(t *testing.T) {
	got := SnapshotPath(`C:\state`)
	if filepath.Base(got) != "proxy-backup.json" {
		t.Fatalf("SnapshotPath = %q", got)
	}
	if DataDirOf(got) != `C:\state` {
		t.Errorf("DataDirOf = %q", DataDirOf(got))
	}
}
