# Manual smoke list

The eval-level suite (`tests/`, `nix flake check`) covers everything that can be
checked without booting. This document is the complementary **manual** pass: the
things that need a real guest, a real host firewall, or a real network path.
Run it after a host rebuild on each platform, and after changes to networking,
the firewall, or the proxy.

Legend: `[ ]` = to check. Commands are shown for a host named `myhost` and
guests `vault` (VM), `box` (container), `proxyvm` (internet VM hosting the
proxy) unless noted.

## Prerequisites (both platforms)

- [ ] `just rebuild` (or the platform rebuild) succeeds and the host module
      generated `~/.config/tartarus/config.toml`:
      `cat ~/.config/tartarus/config.toml` shows `user`, `system`, `flake`,
      and one `[[guests]]` block per enabled guest with the effective `id`.
- [ ] `tartarus list` lists every enabled guest and none of the disabled ones.
- [ ] A disabled/unknown guest is refused, before any build or state change:
      `tartarus start ghost` exits non-zero with a message that the guest is
      "not enabled on this host; set tartarus.guests.ghost.enable = true ...".
      Same for `tartarus status ghost` and the `--container` variants.
- [ ] `tartarus --help` and `tartarus <cmd> --help` work (CLI is on PATH).
- [ ] `~/.ssh/known_hosts_trs` contains the `@cert-authority *.trs ...` line
      and the enabled subnets (`systemctl --user start tartarus-ca-known-hosts`
      if it is missing).

## Linux host

### Bridge + VSOCK (internet VM)

- [ ] `tartarus start vault` (or an internet guest) builds and boots.
      `tartarus status vault` reports running, with a pid.
- [ ] `tartarus cid vault` prints the static id.
- [ ] `tartarus ssh vault` connects over VSOCK
      (`ssh -v` shows `ProxyCommand ... tartarus proxy %h` and a
      `socat ... VSOCK-CONNECT:<id>:22` line). The CA host key validates with no
      fingerprint prompt.
- [ ] Inside the guest: `ip -brief addr` shows `10.200.0.<id>/24`;
      `ping -c1 10.200.0.1` reaches the host.
- [ ] The host can reach the guest: `ping -c1 10.200.0.<id>`;
      `/etc/hosts` has `10.200.0.<id> vault vault.trs`.
- [ ] `tartarus logs vault` shows the console log; `tartarus stop vault` shuts
      it down.
- [ ] A guest with `disableVsock = true` uses TCP: `tartarus ssh <name>` shows
      `ProxyCommand` to the bridge IP/CID 2, and `ss -ltn` on the host shows the
      service ports (65000/65001/27795) bound.

### Container (systemd-nspawn)

- [ ] `tartarus --container start box` boots; `tartarus status box` is running.
- [ ] `tartarus ip box` (or the generated `Host box` SSH entry) resolves to
      `10.201.0.<id>`; `tartarus ssh box` connects over TCP.
- [ ] Inside: `ip -brief addr` shows `10.201.0.<id>/24`; host services are
      reachable via `10.201.0.1`.
- [ ] The `tartarus_container` nftables table only lists exact container
      addresses (the `tartarus_container_hosts` set).

### Host firewall + host proxy

- [ ] `sudo nft list table inet tartarus_vm` and `... tartarus_container` show
      the input chain with `policy drop` at priority -10, and the per-guest
      rules.
- [ ] For a proxy-only guest, the proxy accept rule is in the **same**
      `*_input` chain, not a separate table:
      `sudo nft list table inet tartarus_vm | grep vault-proxy`.
      `sudo nft list tables | grep -w squid` prints nothing.
- [ ] `sudo nft list table inet tartarus_nat` shows the masquerade rules, and -
      when the proxy is guest-hosted - the `proxy-no-masq` return.
- [ ] Host proxy service is running and binds the bridges, never loopback:
      `systemctl --user status tartarus-proxy`;
      `ss -ltnp | grep :3128` lists `10.200.0.1:3128` and `10.201.0.1:3128`
      (and **not** `127.0.0.1:3128`).

### Allowlist hit / deny (proxy-only guest)

Inside a guest with `proxy.enable = true` and `allowHosts = ["example.com"]`:

- [ ] The guest env is written:
      `cat ~/.config/environment.d/10-tartarus.conf` contains uppercase and
      lowercase `http_proxy`/`https_proxy`/`all_proxy`, `NO_PROXY` with the
      subnets, the two bridge host IPs, the vmnet gateway, `localhost`,
      `127.0.0.1` and `.trs`.
- [ ] Allowlisted HTTPS works: `curl -sS https://example.com >/dev/null` (uses
      the proxy via `HTTPS_PROXY`).
- [ ] A non-allowlisted HTTPS host is denied:
      `curl -sS --max-time 5 https://example.org` fails with a proxy 403/DNS
      error.
- [ ] Plain HTTP to an allowlisted host is denied (allowlist is CONNECT/443
      only): `curl -sS --max-time 5 http://example.com` fails.
- [ ] The proxy sees only metadata (client IP, CONNECT host) with `log = true`:
      `journalctl --user -u tartarus-proxy` (no request bodies are possible
      without MITM).

### DNS / SSH drop (proxy-only guest)

- [ ] `getent hosts example.com` fails (the host firewall drops DNS: no
      resolver is reachable; the proxy resolves on the guest's behalf).
- [ ] `ssh -o ConnectTimeout=3 -o BatchMode=yes git@github.com` does not
      connect (port 22 is dropped).
- [ ] `ping -c1 1.1.1.1` fails (ICMP not proxied).
- [ ] Internal host services still work: the clipboard/ssh/sudo fallback ports
      and `*.trs` hosts remain reachable (not sent to the proxy thanks to
      `NO_PROXY`).

### Guest-hosted proxy + cross-kind routing

With `tartarus.proxy.location = "proxyvm"` (`proxyvm` is an internet VM) and a
container client:

- [ ] `sudo nft list table inet tartarus_container` forward chain contains the
      `box-to-proxy` accept for `10.200.0.<proxyid>:3128`.
- [ ] `sudo nft list table inet tartarus_nat` contains the `proxy-no-masq`
      return, so the container's source IP reaches the proxy intact.
- [ ] From the container, `curl -x http://10.200.0.<proxyid>:3128 https://example.com`
      works; with `log = true`, the proxy's log shows the container's
      `10.201.0.<id>` source (not a masqueraded address).
- [ ] Same-kind clients (a VM to a VM-hosted proxy) do not cross the host; only
      the `forward` accept for their own bridge is needed.

### Guest in-guest firewall

For a guest with `firewall.enable = true` and `firewall.location = "guest"`:

- [ ] Inside: `sudo nft list ruleset` shows the `tartarus` output chain with
      `policy drop`, the loopback/established/DNS accepts, the proxy rule and
      the `firewall.allow` entries.
- [ ] An arbitrary outbound connection is dropped; traffic to the subnet and to
      the proxy is allowed.

### Autostart

- [ ] For a guest with `autostart = true`, after logging in:
      `systemctl --user status tartarus-autostart-<name>` is active, and
      `tartarus status <name>` is running.

## macOS host (nix-darwin)

### NAT + TCP

- [ ] `tartarus start vault` builds (via `nix.linux-builder`) and boots.
- [ ] `tartarus ip vault` resolves the vmnet address (ARP lookup by MAC
      `02:00:00:00:00:<hex id>`) and prints `192.168.64.<id + 42>`.
- [ ] `tartarus ssh vault` connects over TCP using `tartarus proxy-ip %h`
      (`ssh -v` shows the `nc <ip> 22` path), and the CA host key validates.
- [ ] Inside the guest: `ip -brief addr` shows `192.168.64.<id + 42>/24`; the
      host gateway `192.168.64.1` answers (e.g. the proxy port).
- [ ] No bridge/VSOCK/nftables exist on the host:
      `ifconfig | grep trs` prints nothing; `pfctl`/nftables are untouched.

### Host proxy

- [ ] The launchd agent is loaded and binds the vmnet gateway:
      `launchctl list | grep tartarus-proxy`;
      `lsof -nP -iTCP:3128 -sTCP:LISTEN` shows `192.168.64.1:3128`
      (not `127.0.0.1`).
- [ ] In a proxied guest, `cat ~/.config/environment.d/10-tartarus.conf` shows
      `HTTP_PROXY=http://192.168.64.1:3128` (and the lowercase twins).
- [ ] Allowlist hit/deny and DNS/SSH drop behave as on Linux (they are enforced
      by the proxy + the guest firewall; there is no host firewall).

### Guest-hosted proxy

- [ ] Rejected as designed: `tartarus.proxy.location` naming a guest must fail
      evaluation on Darwin; only `"host"` is accepted.

## Standalone use of the services (no VM, no tartarus host module)

Import each module directly and set its `tartarus.<service>.*` options; nothing
here needs the tartarus host module or a guest.

- [ ] `sudo-auth-proxy`: build the package and import both halves standalone
      (`nixosModules."sudo-auth-proxy-pam"` for the PAM client, or the legacy
      `nixosModules."sudo-auth-proxy"`; `homeManagerModules."sudo-auth-proxy"`
      for the server). Confirm `sudo` uses the proxy and that a mismatched
      client OID is rejected.
- [ ] `ssh-agent-proxy`: `nixosModules."ssh-agent-proxy"` (host server) and
      `homeManagerModules."ssh-agent-proxy"` (server/bridge/agent/merge);
      confirm the guest's `SSH_AUTH_SOCK` is the merged socket and that
      `ssh-add -l` lists the host keys.
- [ ] `clipboard-bridge`: `nixosModules."clipboard-bridge"` (host server) and
      `homeManagerModules."clipboard-bridge"` (server/client/adminClient); copy
      on one side and paste on the other over `wprs-0`, confirming the mTLS
      handshake succeeds with the tartarus X509 CA and fails with a wrong
      OID/cert.
