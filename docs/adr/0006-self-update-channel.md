# 0006: Self-update — Control plane decides, GitHub serves bytes

**Status:** accepted

The Control plane stores an "expected version" plus an asset URL template (with `{os}`, `{arch}`, `{version}` substitutions). Heartbeat responses carry a `check_update` command pointer when the Agent's reported `agent_version` differs from the expected version. The Agent then fetches the manifest via `GET /v1/agent/update-plan`, downloads the binary from the templated URL (typically a GitHub Releases asset), verifies the SHA256 checksum from a sibling asset, performs an atomic binary swap (POSIX rename on Unix, `.new`/`.old` pattern on Windows), and triggers a service restart. On failed restart within 30s, a supervisor wrapper reverts to the previous binary.

## Considered options

- **GitHub Releases pull (Agent polls Atom feed).** Rejected: operator loses centralized timing control of rollouts; every Agent decides independently when to upgrade.
- **Control-plane-hosted artifacts.** Operator pushes binaries to the Control plane, which serves them. Rejected: turns the Control plane into blob storage; adds bandwidth, disk, and CDN concerns; reinvents what GitHub already does.
- **Hybrid: Control plane decides, GitHub serves bytes (chosen).** Operator owns *when* (push expected_version on Control plane); GitHub owns *what* (CDN-served bytes, free checksums). Decoupling means the artifact source can move (S3, self-hosted) by changing only the URL template.

## Consequences

- Trust path = Operator's control of the GitHub repo + the configured CA on TLS. V2 ships SHA256 verification; sigstore signature verification is a future addition.
- No Apple notarization or Windows code signing in V2. First-run on macOS requires right-click → Open (Gatekeeper override); Windows SmartScreen requires right-click → Properties → Unblock. Documented in `docs/architecture.md`.
- Per-Agent override: `uncluster agent update --pin=vX.Y.Z` holds a specific version (overrides the Control plane's expected). `--unpin` clears.
- Single `stable` channel in V2. `beta` / `nightly` channels deferred.
- Emergency upgrade latency = one heartbeat interval (~10s) plus download time.
