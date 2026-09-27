# Host <-> guest shares and the ownership fixups they need.
#
# Built-in shares on every VM:
#   ro-store       read-only /nix/store backing /nix/.rw-store (store-overlay)
#   shared         host ~/shared/<vm> -> guest ~/shared (when sharedFolder)
#   tartarus-ssh   CA-signed host key directory
#   tartarus-x509  mTLS client certificate directory
#
# Ad-hoc `vm start --mount` shares arrive through MICROVM_EXTRA_SHARES.
# Containers do not use shares: the host bind-mounts the same directories
# directly, so this only pre-creates their mount points.
#
# Read-only shares are genuinely read-only on Linux (the hypervisor honours
# `readOnly`) but *not* on macOS/vfkit, which ignores it. There, every
# read-only share is re-sourced from a read-only Nix store snapshot so the guest
# cannot write the host's live files. See `nix/lib/shares.nix` for the policy
# and the `snapshot = false` opt-out.
{
  lib,
  pkgs,
  tartarusGuest,
  mkServiceSystem,
  ...
}: let
  inherit
    (lib)
    any
    concatMap
    dirOf
    filter
    hasPrefix
    mkIf
    mkMerge
    optional
    optionals
    unique
    ;
  g = tartarusGuest;
  p = g.platform;
  user = g.user.name;
  sharePolicy = import ../lib/shares.nix {inherit lib;};

  kindDir =
    if g.isVm
    then "microvm"
    else "containers";

  # Every share keeps the platform's proto: vfkit only accepts virtiofs;
  # Linux keeps whatever the caller declared (built-ins and ad-hoc are 9p).
  appShares = map (s: s // {proto = p.shareProto;}) g.shares;
  extraShares = map (s: s // {proto = p.shareProto;}) g.extraShares;

  rawShares =
    appShares
    ++ [
      {
        tag = "ro-store";
        source = "/nix/store";
        mountPoint = "/nix/.ro-store";
        proto = p.shareProto;
        readOnly = true;
        # Already immutable; never copy the whole store.
        snapshot = false;
      }
    ]
    ++ optional g.sharedFolder {
      tag = "shared";
      # Keyed by guest name (with instance suffix) so numbered instances do not
      # fight over the same host directory.
      source = "${g.hostHome}/shared/${g.name}";
      mountPoint = "${g.user.home}/shared";
      proto = p.shareProto;
    }
    ++ [
      {
        tag = "tartarus-ssh";
        # Always the base guest's cert -- only base guests have host-side CA
        # infrastructure provisioned, and all instances of a guest share the
        # same host key/cert.
        source = "${g.hostHome}/.local/share/tartarus/ssh/machines/${kindDir}/${g.baseName}";
        mountPoint = "/etc/tartarus/ssh";
        proto = p.shareProto;
        readOnly = true;
        # Private host keys: never copy into the world-readable store.
        snapshot = false;
      }
      {
        tag = "tartarus-x509";
        source = "${g.hostHome}/.local/share/tartarus/x509/machines/${kindDir}/${g.baseName}";
        mountPoint = "/etc/tartarus/x509";
        proto = p.shareProto;
        readOnly = true;
        # Private client keys: never copy into the world-readable store.
        snapshot = false;
      }
    ]
    # CA key material for the nested containers. ONE share per material type
    # for the whole VM, not one per container: Apple's Virtualization.framework
    # caps virtio-fs devices at 26, so six containers each needing ssh+x509 on
    # top of their user shares would exhaust it. The `containers/` parent holds
    # every inner container's material as `<name>/...`; container-host.nix binds
    # the per-container subdirectory at /etc/tartarus/{ssh,x509}. Read-only and
    # never snapshotted: they hold private host/client keys. `vm.action_start`
    # provisions each inner container's certs before building the VM.
    ++ optionals ((g.innerContainers or []) != []) [
      {
        tag = "ti-certs-ssh";
        source = "${g.hostHome}/.local/share/tartarus/ssh/machines/containers";
        mountPoint = "/var/lib/tartarus-inner/certs/ssh";
        proto = p.shareProto;
        readOnly = true;
        snapshot = false;
      }
      {
        tag = "ti-certs-x509";
        source = "${g.hostHome}/.local/share/tartarus/x509/machines/containers";
        mountPoint = "/var/lib/tartarus-inner/certs/x509";
        proto = p.shareProto;
        readOnly = true;
        snapshot = false;
      }
    ]
    # ONE share for every inner container's `~/shared`: the parent
    # `~/shared/<name>` tree, bind-mounted per-container (same device cap).
    ++ optional (any (inner: inner.cfg.sharedFolder or false) (g.innerContainers or [])) {
      tag = "ti-shared";
      source = "${g.hostHome}/shared";
      mountPoint = "/var/lib/tartarus-inner/shared";
      proto = p.shareProto;
    }
    # The inner containers' user shares. A share whose source is store-snapshotted
    # (read-only on Darwin) is deliberately NOT exported as a device: the VM
    # already reaches the host store through `ro-store`, so `container-host.nix`
    # bind-mounts the snapshot path straight from `/nix/store`, saving a device
    # per such share. Everything else gets one device mounted under the
    # container's inner directory (bind-mounted inward by container-host.nix).
    #
    # The tag is kept short and keyed by the inner id (`ti<id>-...`): vfkit
    # rejects virtiofs tags longer than 36 bytes.
    ++ concatMap (
      inner:
        map (s: {
          tag = "ti${toString inner.id}-s-${s.tag}";
          source = s.source;
          mountPoint = "/var/lib/tartarus-inner/${inner.name}/shares/${s.tag}";
          proto = p.shareProto;
          readOnly = s.readOnly or false;
          snapshot = s.snapshot or true;
        })
        (filter (s: !(sharePolicy.needsStoreSnapshot p s)) (inner.cfg.shares or []))
    ) (g.innerContainers or [])
    ++ extraShares;

  isWritableNinePShare = s: (s.proto or "9p") == "9p" && !(s.readOnly or false);

  # 9p's default securityModel ("none") always reports files to the guest as
  # owned by 0:0. "mapped" stores guest-visible ownership as host-side xattrs
  # instead, seeded once by fixup-share-perms. Only writable shares need it.
  #
  # On macOS/vfkit `readOnly` is a no-op (see ../lib/shares.nix), so every
  # read-only share is additionally re-sourced from a read-only Nix store
  # snapshot there. `snapshot` is tartarus-internal and stripped before the
  # shares reach `microvm.shares`.
  shares = map (s: builtins.removeAttrs s ["snapshot"]) (
    map (
      s:
        if sharePolicy.needsStoreSnapshot p s
        then s // {source = sharePolicy.storeSnapshot s.tag s.source;}
        else s
    )
    (map (
        s:
          if isWritableNinePShare s
          then s // {securityModel = s.securityModel or "mapped";}
          else s
      )
      rawShares)
  );

  writableShareMountPoints = map (s: s.mountPoint) (filter isWritableNinePShare shares);

  # A share whose mount point is nested under the guest home (e.g.
  # ~/.config/rmpc) needs its parent to exist before the 9p mount runs;
  # otherwise systemd auto-creates the parent as root and blocks the user's own
  # home-manager activation from writing under it. Pre-declared as tmpfiles.
  shareMountParents = unique (
    filter (d: d != g.user.home && hasPrefix "${g.user.home}/" d)
    (map (s: dirOf s.mountPoint) (appShares ++ g.extraShares))
  );

  persistentHome = g.vm.persistentHome;

  shareFixupService = mkServiceSystem {
    name = "fixup-share-perms";
    description = "Fix up guest-visible ownership of writable 9p shares";
    # Leading "-": 9p "mapped" cannot store ownership xattrs on symlinks, so
    # chown -R exits non-zero on any share containing one -- expected.
    command = "-${pkgs.coreutils}/bin/chown -R ${user}:users ${lib.escapeShellArgs writableShareMountPoints}";
    scope = "system";
    extraSystemdUnitConfig.RequiresMountsFor = writableShareMountPoints;
    extraSystemdServiceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
    };
  };

  persistentHomeFixupService = mkServiceSystem {
    name = "fixup-persistent-home";
    description = "Fix up ownership of persistent home volume";
    # Leading "-": virtiofs shares mounted under the home may reject chown.
    command = "-${pkgs.coreutils}/bin/chown -R ${user}:users ${g.user.home}";
    scope = "system";
    after = ["local-fs.target"];
    extraSystemdUnitConfig.Before = ["home-manager-user.service"];
    extraSystemdServiceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
    };
  };
in {
  imports = optionals g.isVm [
    (mkIf (writableShareMountPoints != []) shareFixupService)
    (mkIf persistentHome.enable persistentHomeFixupService)
  ];

  config = mkMerge [
    (mkIf g.isVm {
      microvm = {
        inherit shares;

        # Auto-created on first boot, persists across restarts in the per-VM
        # state dir, wiped by `tartarus stop --purge`. The nix-store overlay
        # lives in store-overlay.nix.
        volumes = optional persistentHome.enable {
          image = "home.img";
          mountPoint = g.user.home;
          size = persistentHome.size;
        };
      };
    })

    {
      systemd.tmpfiles.rules =
        (map (d: "d ${d} 0755 ${user} users -") shareMountParents)
        ++ optionals g.isVm (
          optional persistentHome.enable "z ${g.user.home} 0755 ${user} users -"
        );
    }
  ];
}
