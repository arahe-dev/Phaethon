# Releases

## What a release contains

```
phaethon-windows-amd64.zip
phaethon-windows-arm64.zip
phaethon-linux-amd64.tar.gz
phaethon-linux-arm64.tar.gz
phaethon-darwin-amd64.tar.gz
phaethon-darwin-arm64.tar.gz
SHA256SUMS.txt
```

One self-contained executable per platform. **Not** one binary that runs
everywhere: Go still needs a build per OS and architecture, and pretending
otherwise would be a lie in the release notes.

Every archive contains the binary. The Windows zip also contains the installer
and the install script.

## Cutting a release

```bash
# 1. gates, uncached
gofmt -l .                      # must print nothing
go vet ./...
go test -count=1 ./...
go test -race -count=1 ./...

# 2. artifacts
./scripts/build-all.ps1 -Out dist -Checksums

# 3. tag
git tag -a v0.1.0 -m "v0.1.0"
git push origin v0.1.0
```

The release workflow runs the same gates again on the tag before building. A
release must never depend on a separate workflow having passed earlier.

## Release criteria

Before tagging, every one of these must hold:

- [ ] `gofmt -l .` prints nothing
- [ ] `go vet ./...` and both test runs pass **uncached** — a cached pass is not a pass
- [ ] All six targets build
- [ ] Version output reports the build commit
- [ ] `phaethon doctor` reports ready on a machine that was set up from the artifact
- [ ] No personal data: no account identifiers, endpoints, tokens or hostnames
- [ ] No secrets in the working tree or in history
- [ ] Stable and experimental features are clearly separated in the docs
- [ ] Mermaid diagrams render on GitHub
- [ ] Every link in README and docs resolves
- [ ] Install, setup and rollback are documented

## Versioning

Semantic versioning. The CLI surface and the configuration schema are the
contract; internal package APIs are not.

## The claim on the release page

> Phaethon is a local selective routing proxy. Healthy traffic remains direct.
> When Fairy detects that an eligible destination's direct path is unusable,
> Phaethon can use the user's own Cloudflare relay.

Do not claim zero latency, zero overhead, zero dependencies, or universal
firewall bypass. None of them is true, and a reader who checks will find that out.
