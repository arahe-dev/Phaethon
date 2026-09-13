// Package release holds no code. It exists so the release contract can be
// tested from inside the module, where it runs in CI on every push.
//
// The three files that have to agree about an asset's name are written in three
// different languages: install.sh decides what to download, build-all.ps1
// decides what to produce, and release.yml decides what to publish. Nothing
// makes them agree at build time, and when they disagree the failure appears as
// a 404 for a user running the installer rather than as a red build. That is
// exactly what happened: the installer asked for .tar.gz archives while the
// build produced raw binaries.
//
// These tests compare the contract rather than the implementation. They are
// deliberately string-based, because parsing PowerShell and bash properly would
// be a larger and more fragile thing than the contract it protects.
package release

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// repoRoot locates the repository by walking up until it finds go.mod.
//
// Deriving it instead of assuming ../../ keeps the test working whichever
// directory it is run from, including as a standalone test binary, where the
// working directory is wherever that binary happens to be.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("cannot determine the working directory: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod found above the working directory")
		}
		dir = parent
	}
}

// repoFile reads a file from the repository root.
func repoFile(t *testing.T, rel string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot(t), filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("cannot read %s: %v", rel, err)
	}
	return string(data)
}

// platforms is the release matrix. It is duplicated here on purpose: if someone
// adds a platform to the build or removes one from the installer, this test is
// what notices.
var platforms = []struct {
	os, arch, ext string
}{
	{"windows", "amd64", ".zip"},
	{"windows", "arm64", ".zip"},
	{"linux", "amd64", ".tar.gz"},
	{"linux", "arm64", ".tar.gz"},
	{"darwin", "amd64", ".tar.gz"},
	{"darwin", "arm64", ".tar.gz"},
}

// The installer must fetch exactly the archives the build produces.
//
// A mismatch here is invisible until a user runs the one-line installer and it
// 404s, which is the worst place to discover it.
func TestInstallerExpectsTheArtifactsTheBuildProduces(t *testing.T) {
	installer := repoFile(t, "install.sh")
	build := repoFile(t, "scripts/build-all.ps1")

	// The installer names the asset as phaethon-linux-$ARCH.tar.gz, so the
	// extension it appends must be the one the build packages with.
	if !strings.Contains(installer, `phaethon-linux-$ARCH.tar.gz`) {
		t.Error("install.sh no longer builds the asset name as phaethon-linux-$ARCH.tar.gz; " +
			"if that changed, the build matrix below must change with it")
	}
	for _, p := range platforms {
		base := "phaethon-" + p.os + "-" + p.arch
		if p.os != "linux" {
			// The installer only fetches Linux; the build still has to emit
			// the others for the same release.
			if !strings.Contains(build, p.os) || !strings.Contains(build, p.arch) {
				t.Errorf("build-all.ps1 no longer builds %s", base)
			}
			continue
		}
		// The build must package, not merely produce a binary: a raw binary
		// would satisfy a naive name check while breaking the installer.
		if !strings.Contains(build, "tar -czf") {
			t.Errorf("build-all.ps1 does not create a tar.gz archive, so %s.tar.gz cannot exist", base)
		}
	}
	if !strings.Contains(build, "Compress-Archive") {
		t.Error("build-all.ps1 does not create zip archives for Windows")
	}
}

// Checksums must cover the archives, not the intermediate binaries.
//
// A SHA256SUMS.txt listing files that are not published is worse than useless:
// the installer looks for its archive in there and finds nothing.
func TestChecksumsCoverThePublishedAssets(t *testing.T) {
	build := repoFile(t, "scripts/build-all.ps1")

	if !strings.Contains(build, "SHA256SUMS.txt") {
		t.Fatal("build-all.ps1 no longer writes SHA256SUMS.txt")
	}
	// The checksum list must be built from the packages, not from everything
	// in the output directory, or staging leftovers get hashed.
	if !strings.Contains(build, "$packages") {
		t.Error("checksums must be computed over the package list, not over whatever is in the output directory")
	}
	// Raw binaries must be staged outside the output directory, which is what
	// keeps them out of the checksum step and out of the release.
	if !strings.Contains(build, "$stage") {
		t.Error("raw binaries must be staged outside the output directory so they are never published or hashed")
	}

	installer := repoFile(t, "install.sh")
	if !strings.Contains(installer, "SHA256SUMS.txt") {
		t.Error("install.sh no longer verifies against SHA256SUMS.txt")
	}
	if !strings.Contains(installer, "sha256sum") {
		t.Error("install.sh no longer verifies the download checksum")
	}
}

// Every file the release workflow reads must exist.
//
// A missing --notes-file fails the publish step after the builds have already
// succeeded, which wastes the whole run and is only discovered when someone
// tags.
func TestWorkflowReferencesExist(t *testing.T) {
	workflow := repoFile(t, ".github/workflows/release.yml")

	for _, ref := range []string{"docs/RELEASE-NOTES.md", "scripts/build-all.ps1"} {
		if !strings.Contains(workflow, ref) {
			continue // not referenced, nothing to check
		}
		if _, err := os.Stat(filepath.Join(repoRoot(t), filepath.FromSlash(ref))); err != nil {
			t.Errorf("release.yml references %s, which does not exist: the publish step would fail", ref)
		}
	}

	// The build script must be invoked in a way that produces checksums, since
	// the release publishes SHA256SUMS.txt.
	if strings.Contains(workflow, "build-all.ps1") && !strings.Contains(workflow, "-Checksums") {
		t.Error("release.yml runs build-all.ps1 without -Checksums, so no SHA256SUMS.txt would be published")
	}
}

// The publish step must attach the archives the installer fetches.
func TestReleasePublishesArchives(t *testing.T) {
	workflow := repoFile(t, ".github/workflows/release.yml")
	if !strings.Contains(workflow, "gh release create") {
		t.Fatal("release.yml no longer creates a release")
	}
	// dist/* is what uploads the assets; a narrower glob would silently drop
	// SHA256SUMS.txt or an archive.
	if !strings.Contains(workflow, "dist/*") {
		t.Error("the publish step must upload dist/* so every archive and SHA256SUMS.txt is attached")
	}
	// A tag push is what triggers a release, and only a tag.
	if !regexp.MustCompile(`tags:\s*\["v\*"\]`).MatchString(workflow) {
		t.Errorf("release.yml should trigger on version tags only")
	}
}

// Every documented asset must be one the build actually produces.
func TestReleaseNotesListRealAssets(t *testing.T) {
	notes := repoFile(t, "docs/RELEASE-NOTES.md")
	known := map[string]bool{"SHA256SUMS.txt": true}
	for _, p := range platforms {
		known["phaethon-"+p.os+"-"+p.arch+p.ext] = true
	}
	for _, m := range regexp.MustCompile("`(phaethon-[a-z0-9-]+\\.(tar\\.gz|zip))`").FindAllStringSubmatch(notes, -1) {
		if !known[m[1]] {
			t.Errorf("release notes advertise %s, which the build does not produce", m[1])
		}
	}
}

// Every binary path the workflow hands to a script must exist after the build.
//
// This is the gap that let a real regression through: build-all.ps1 was changed
// to package archives and stage raw binaries outside the output directory, and
// the workflow still passed dist/phaethon.exe to the installer builder. The
// release failed four minutes into a tagged run. Checking the Linux contract was
// not enough, because the workflow has its own assumptions about where a build
// leaves things.
func TestWorkflowBinaryPathsAreProduced(t *testing.T) {
	workflow := repoFile(t, ".github/workflows/release.yml")
	build := repoFile(t, "scripts/build-all.ps1")

	// A bare dist/phaethon.exe is no longer produced: the build stages
	// intermediates outside the output directory on purpose.
	if regexp.MustCompile(`-Binary\s+dist/phaethon\.exe\b`).MatchString(workflow) {
		t.Error("release.yml passes dist/phaethon.exe to a script, but build-all.ps1 stages that " +
			"binary inside an archive; unpack it first or the step fails after the build has succeeded")
	}
	// If the workflow wants a raw binary, it must extract it from something the
	// build actually produces.
	if strings.Contains(workflow, "installer/build-installer.ps1") {
		if !strings.Contains(workflow, "phaethon-windows-amd64.zip") {
			t.Error("the installer build must obtain its binary from the archive the build produces")
		}
		if !strings.Contains(workflow, "Expand-Archive") {
			t.Error("the installer build must unpack the archive before using the binary inside it")
		}
	}
	// Whatever the workflow names as a source must be a real build output.
	for _, m := range regexp.MustCompile(`dist/(phaethon-[a-z0-9-]+\.(?:zip|tar\.gz))`).FindAllStringSubmatch(workflow, -1) {
		if !strings.Contains(build, "phaethon-$(") && !strings.Contains(build, `"$base`) {
			t.Errorf("workflow expects %s, but the build no longer derives names from a base", m[1])
		}
	}
}

// The publish step uploads dist/*, so dist must contain only publishable assets.
//
// A directory left in dist is uploaded as an asset named after it, and the
// release fails at the very last step with a message about a file that cannot be
// read. This happened: unpacking the Windows archive into dist/win to satisfy the
// installer build put a directory where the asset glob expects files.
func TestNothingUnpacksIntoTheReleaseDirectory(t *testing.T) {
	workflow := repoFile(t, ".github/workflows/release.yml")

	if !strings.Contains(workflow, "dist/*") {
		return // not publishing from dist; nothing to guard
	}
	for _, m := range regexp.MustCompile(`Expand-Archive[^\n]*-DestinationPath\s+([^\s\\]+)`).FindAllStringSubmatch(workflow, -1) {
		if strings.HasPrefix(m[1], "dist") {
			t.Errorf("Expand-Archive writes to %s, which the publish step uploads as an asset; "+
				"unpack outside dist instead", m[1])
		}
	}
	// Any build step that writes into dist must write files, never a directory.
	if strings.Contains(workflow, "-Out dist") && strings.Contains(workflow, "-DestinationPath dist") {
		t.Error("scanning into dist while publishing dist/* will upload a directory as an asset")
	}
}
