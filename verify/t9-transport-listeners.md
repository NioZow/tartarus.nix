# Verify — T9 transport listeners

- commit: `096f3443f430bf851e5ad25a1db026c3a9300cab` (submodule HEAD) + uncommitted working tree (fixes applied)
- spec: `docs/design/transport-listeners.md`
- interpreter: `/nix/store/2q42832fl23000743p7ycmh0kmvnazm4-python3-3.13.15-env/bin/python` (with `TMPDIR=/tmp`)

## Verdict

**PASS.** The multi-transport server rework is conformant. The blocking
ssh-bridge regression and the two partial findings from the previous report are
fixed and independently re-probed. One low-severity edge case remains (duplicate
`unix` socket paths shadow rather than fail), and `nix flake check` still fails
on a pre-existing, unrelated check that also fails at parent commit `096f344`.

### Re-verification of the three fixes

1. **ssh bridge timeouts — FIXED.** `mkSecurityOptions` gained
   `withTimeouts ? false` (`nix/packages/ssh-agent-proxy/default.nix:102,135`);
   the bridge opts in at `:517-519`. Rendering a standalone HM config with
   `tartarus.ssh-agent-proxy.bridge.enable = true` now succeeds and its TOML
   carries the timeouts in `[security]`:
   ```
   [security]
   client_auth = "transport"
   connect_timeout = 10.0
   decision_timeout = 120
   handshake_timeout = 10.0
   server_auth = "transport"
   transport_encryption = "mtls"
   ```
   The server listener `security` (`:249`) does **not** opt in, so timeouts
   remain listener-level there (correct).
2. **sudo `transportDefaults` TTL/skew — FIXED.** `responseTtl`/`clockSkew`
   are now `nullableOpt`-aware (`nix/packages/sudo-auth-proxy/default.nix:126,130`),
   so sparse entries default to `null` and are pruned by the render. Rendering
   `transportDefaults.security.responseTtl = 60` emits:
   ```toml
   [transport_defaults.security]
   clock_skew = 5
   response_ttl = 60          # survives
   ...
   [[transports]]             # entry security omits response_ttl/clock_skew
   ...
   [transports.security]
   transport_encryption = "none"
   ```
3. **ssh ambiguity — FIXED.** The flat-key guard now includes `security`/`mtls`
   (`ssh-agent-proxy.py:688`). Probe with a `transports` doc plus a flat
   `[security]`:
   `ValueError: transports cannot be combined with the flat 'security' key (the configuration is ambiguous)`.

All parent hosts that previously failed now evaluate:

```
nixosConfigurations.mofos               -> /nix/store/7p6af2vx…-nixos-system-mofos-26.05…    (exit 0)
nixosConfigurations.stream              -> /nix/store/qg7hxpl5…-nixos-system-stream-26.05…   (exit 0)
homeConfigurations.linux                -> /nix/store/ndnqh1zj…-home-manager-generation      (exit 0)
```

---

## Criterion 1 — original warn/throw gone; mixed vsock+tcp yields two listeners

**VERDICT: PASS**

- `nix/host/services.nix` contains no `lib.warn`/`throw` (only a comment noting
  they are gone); the old `sudoTransport`/`sshTransport`/`mkTransport` collapse
  was removed.
- Real host:
  ```
  nix eval --impure --json "path:/home/user/.config/nixcfg#nixosConfigurations.zeus.config.home-manager.users.user.tartarus.sudo-auth-proxy.server.transports"
  ```
  → `['vsock', 'tcp']` (exit 0). The generated zeus TOML contains both
  `[[transports]] cid=2 type="vsock"` and
  `[[transports]] host="10.200.0.1" port=65001 type="tcp"`.
- `nix eval --impure --file tests/default.nix --json` passes
  `hostSudoMixedTransports`, `hostSudoUnixPlusCallback`, `hostSshMixedTransports`,
  `hostSshUnixPlusCallback` (the old `throw` case now evaluates).

## Criterion 2 — multi-listener bind, all-or-nothing, cleanup on failure

**VERDICT: PASS** (one low-severity edge case, finding 1)

- Code: `nix/packages/sudo-auth-proxy/sudo-auth-proxy.py:3778` `run_server`
  binds every listener in a loop, attaches `_security`, and on any
  `BaseException` closes the already-bound listeners before re-raising
  (`:3817-3821`); `_close_listener` (`:3759`) `server_close()` +
  `transport.cleanup()`, guarded by `_sap_serving`.
- Falsification (`/tmp/probe_runtime.py`):
  - listener 2 = tcp port already in use → `OSError`; listener 1's unix socket
    unlinked (path gone).
  - listener 2 = unix mTLS with missing cert → `FileNotFoundError`; listener 1
    cleaned up.
  - ssh analogue (`/tmp/probe_ssh_runtime.py`) behaves the same
    (`run_proxy`, `ssh-agent-proxy.py:2592`).
- **Finding 1 (low, remaining):** two `unix` listeners on the *same* path do
  not fail — `_prepare_unix_socket` (`sudo-auth-proxy.py:3008-3018`) unlinks any
  same-uid socket before binding, so listener 2 replaces listener 1 and the
  server starts. Probe A: `exceptions: []`, `server still alive: True`.
  No fd/file leak, but listener 1 becomes unreachable. The spec §4.6 says
  duplicate socket paths are "a runtime bind error"; the implementation takes
  the unlink branch. Not a violation of criterion 2 as written.

## Criterion 3 — per-listener security isolation

**VERDICT: PASS**

- sudo `Handler.handle` reads `_config`/`_transport`/`_security` off
  `self.server` (`sudo-auth-proxy.py:3490-3506`); `run_server` creates one
  dynamic server class per view and `setattr(server, "_security", security)`
  (`:3810`). `Transport.listen` puts the per-listener `_config`/`_transport` in
  the class dict (`:3127-3128`). No shared mutable state.
- ssh `Handler.setup` reads `self.server.app_config`, `listener_config.resolution`,
  `ssl_context`, `_mtls_config` (`ssh-agent-proxy.py:1548-1565`);
  `_bind_listener` sets them per server (`:2575-2579`).
- Tests `test_per_listener_security_isolation` (sudo) and
  `test_create_ssl_context_is_per_listener` (ssh) pass.

## Criterion 4 — multiple same-kind listeners

**VERDICT: PASS**

- `test_run_server_binds_two_unix_listeners_with_distinct_acls` (sudo): two
  `unix` entries with different ACL rules, both reachable, both unlinked on
  shutdown. `UnixTransport.cleanup` (`sudo-auth-proxy.py:3296-3308`) unlinks
  only when the path inode equals the instance's `_bound_ino`.
- ssh `test_run_proxy_binds_two_unix_listeners` + `_unlink_listener_socket`
  (`ssh-agent-proxy.py:2583`) likewise.

## Criterion 5 — legacy flat Python config

**VERDICT: PASS**

- `sap.listener_views` returns `[config]` when `transports` is absent/empty
  (`sudo-auth-proxy.py:617-619`); `validate_document_schema` falls back to
  `validate_config_schema` (`:966-968`). ssh `Config.load` falls back to
  `_parse_listener_from_flat` (`ssh-agent-proxy.py:705-706`).
- Probe (`/tmp/probe_listeners.py`): `examples/sudo-auth-proxy-server.toml` → 1
  view `transport=vsock`; `examples/ssh-agent-proxy-server.toml` → 1 listener
  `transport=unix`. New multi-listener examples expand to 3 (sudo:
  vsock/tcp/unix) and 2 (ssh: vsock/unix).

## Criterion 6 — ambiguity rejected

**VERDICT: PASS**

- sudo: `validate_document_schema` (`sudo-auth-proxy.py:970-974`) rejects a
  document with `transports` plus any flat `transport`/`security`/`mtls`/`acl`.
  Probe: both raise `SecurityConfigError`.
- ssh: the guard now rejects flat `transport`/`tcp_bind`/`vsock_port`/**`security`**/**`mtls`**
  (`ssh-agent-proxy.py:688`). Probe:
  `ValueError: transports cannot be combined with the flat 'security' key (the configuration is ambiguous)`.
  Both flat `[security]` and flat `transport` alongside `transports` are refused.

## Criterion 7 — empty listeners refused

**VERDICT: PASS**

- sudo `mkServerAssertions` (`sudo-auth-proxy/default.nix:563-566`) and ssh
  `serverAssertions` (`ssh-agent-proxy/default.nix:769`) fail evaluation when
  `enable = true` and `transports == []`.
- Eval suite passes `server-requires-a-listener` for both services.

## Criterion 8 — client/bridge unchanged

**VERDICT: PASS**

- Python client/bridge is byte-for-byte unchanged: sudo `run_client` identical;
  ssh `run_client`, `RemoteConnection`, `ClientHandler`, `run_merge` identical
  (diffed against `git show HEAD`).
- Nix bridge regression fixed (see re-verification 1): `bridge.enable = true`
  evaluates, the bridge TOML carries `connect_timeout`/`handshake_timeout`/
  `decision_timeout` under `[security]`, and the real hosts that use the bridge
  (`mofos`, `stream`, `home/linux`) all evaluate.
- Coverage note: the eval suite still has no direct
  `tartarus.ssh-agent-proxy.bridge` fixture; the bridge path is now exercised
  indirectly by those host configurations.

## Criterion 9 — default equivalence / listener-level timeouts

**VERDICT: PASS**

- ssh `connect_timeout`/`handshake_timeout`/`decision_timeout` land at the
  listener level (`_parse_listener`, `ssh-agent-proxy.py:779-787`); the rendered
  server TOML puts them in `[transport_defaults]`/entries. The bridge keeps its
  own `[security]` timeouts (criterion 8).
- sudo `transportDefaults.security.responseTtl`/`clockSkew` now survive the
  Python deep-merge (re-verification 2). Out-of-the-box single-listener
  equivalence otherwise holds (`auto` resolves `tcp→mtls`/`unix→none`).

## Criterion 10 — no regressions

**VERDICT: PASS**

- Python suite: `python -m pytest -q` → **430 passed, 1 skipped**.
- Eval suite: `nix eval --impure --file tests/default.nix --json` → **189 passed**
  (all transport fixtures present).
- Parent hosts: `zeus` and `athena` evaluate; previously-failing `mofos`,
  `stream`, and `homeConfigurations.linux` now evaluate (exit 0).
- Firewall: `nix/host/firewall.nix:251-256` opens `tcp dport 65001` for a
  tcp-capable sudo guest; the generated zeus `tartarus_container` table contains
  `ip saddr @tartarus_container_hosts tcp dport 65001 counter accept comment
  "sudo-auth-proxy-tcp"`. ssh is guarded by the `!= "unix"` marker check.
- **Caveat (pre-existing, not caused by this change):**
  `nix flake check --impure` (and `--all-systems`) still fails on
  `container-host/nested-rosnapshot-no-device` ("a store-snapshotted inner share
  still costs a virtiofs device"). The same test fails identically in a clean
  worktree at parent commit `096f344` while the plain eval suite passes it — a
  pre-existing `tests/suite.nix` (`source = ./.;` at `:1714`, check `:2380`)
  flake-vs-path discrepancy, unrelated to transport listeners. So the literal
  T9 gate `nix flake check` does not pass, independent of this change.

---

## Remaining counterexamples / uncertainties

1. **Duplicate `unix` socket paths do not fail** (low): the second listener
   unlinks and shadows the first (`sudo-auth-proxy.py:3018`; ssh via
   `_prepare_unix_socket`). No leak, but a silently unreachable listener and a
   config the spec calls a bind error does not error.
2. **`nix flake check` pre-existing failure** on
   `container-host/nested-rosnapshot-no-device` (fails at HEAD too). Spec T9's
   `nix flake check` acceptance is not literally met for reasons unrelated to
   this change.
3. **Bridge eval coverage gap**: no `tartarus.ssh-agent-proxy.bridge` fixture in
   `tests/suite.nix`; the fix is verified by direct rendering and by
   `mofos`/`stream`/`home/linux` evaluation.

## Repro index

- `/tmp/render-ssh-bridge.nix` — bridge config render (fix 1 + criterion 8).
- `/tmp/render-toml.nix` — sudo TOML probes, incl. `responseTtl` (fix 2 +
  criterion 9).
- `/tmp/probe_listeners.py` — criteria 5/6 (legacy examples, ambiguity).
- `/tmp/probe_runtime.py` — criteria 2/4 (sudo failure cleanup, duplicate path).
- `/tmp/probe_ssh_runtime.py` — ssh runtime isolation/failure cleanup.
- `/tmp/render-ssh.nix` — ssh server TOML probe.

No source file was modified; only this report was written.
