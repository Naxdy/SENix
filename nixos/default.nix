{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib) mkOption types;

  cfg = config.security.selinux;

  # The Nix store is immutable, so SELinux labels cannot be written onto it
  # directly; they are carried by a metadata SquashFS and presented through a
  # writable overlay (metacopy) so the store stays untouched. This is packaged
  # as `selinux-store-overlay`; the `selinux-relabel` entry point below drives it
  # and then labels the writable non-store root.
  storeOverlaySetup =
    # bash
    ''
      set -eu

      setupStoreOverlay() {
        upper=/run/selinux/overlay
        store=/run/selinux/store

        # Always (re-)establish the overlay, but never stack it a second time.
        # A switch unmounts `/nix/store`; if we only set the overlay up on the
        # first run, a switch would leave the store without the metacopy layer
        # and therefore without the labels (store files then report `unlabeled_t`).
        # If the metacopy is already mounted (the unbind/remount of the store is
        # still busy, or this is an idempotent re-run), mounting again would stack
        # it past the kernel's depth limit, so only mount when `/proc/self/mounts`
        # does not already carry our upperdir.
        mkdir -p /run/selinux "$upper" "$store"
        mount -t tmpfs -o size=64m,mode=0755 tmpfs "$upper" 2>/dev/null || true
        mkdir -p "$upper/upper" "$upper/work"
        # The real store, exposed as the lower layer so every store path (past,
        # present, or added at runtime with nix build) stays visible with data.
        mount --bind /nix/store "$store" 2>/dev/null || true
        if ! grep -q 'upperdir=/run/selinux/overlay/upper' /proc/self/mounts; then
          # Overlay a writable upper over the store: labels written via metacopy
          # land in the tmpfs upper while file data continues to come from the
          # immutable store. NixOS's own `/nix/store` is already an overlay
          # (`.ro-store`/`.rw-store`), so skipping this on an idempotent re-run
          # keeps us within the overlayfs depth limit.
          mount -t overlay overlay \
            -o "lowerdir=$store,upperdir=$upper/upper,workdir=$upper/work,metacopy=on" \
            /nix/store 2>/dev/null || true
        fi

        # Label the store directly from the loaded policy's file_contexts instead
        # of a baked metadata image. `restorecon -R` walks the store and writes
        # the labels through the metacopy overlay onto the writable upper, so the
        # underlying `/nix/store` never receives any xattrs and stays immutable.
        # (`setfiles` on the `/nix/store` mount point does not descend; the
        # recursive `restorecon` does.) The glob rules in
        # `security.selinux.modules.*.fileContext` label any store package without
        # having to declare it.
        ${pkgs.policycoreutils}/bin/restorecon -R -F /nix/store 2>/dev/null || true
      }

        setupStoreOverlay
    '';

  storeOverlayScript = pkgs.writeShellApplication {
    name = "selinux-store-overlay";
    runtimeInputs = [
      pkgs.util-linux
      pkgs.coreutils
      pkgs.attr
      pkgs.gnugrep
      pkgs.policycoreutils
    ];
    text = storeOverlaySetup;
  };

  # A single relabel entry point: label the immutable store via the metadata
  # overlay (which provides a writable upper), then `setfiles` the writable
  # non-store root (`/etc`, `/var`, ...) from the policy's file_contexts.
  selinuxRelabelSetup =
    # bash
    ''
      set -eu

      relabel() {
        # `selinux-store-overlay` mounts the metadata overlay on `/nix/store`
        # only once and is idempotent (it skips re-mounting if the store overlay
        # is already active with the same metadata; re-mounting would stack a
        # second overlay and exceed the overlayfs depth limit). It does not rely
        # on an initrd-time run, so nothing clears the marker here.
        ${storeOverlayScript}/bin/selinux-store-overlay

        fc=/run/selinux/${cfg.type}/active/file_contexts
        pol=/run/selinux/${cfg.type}/active/policy.kern
        if [ -f "$fc" ] && [ -f "$pol" ]; then
          # Label the writable non-store root. `/home`, `/opt` and `/srv` may be
          # absent on a fresh system, so only pass paths that exist. The root
          # directory itself must be `root_t` (not `unlabeled_t`) so daemons can
          # traverse it.
          ${pkgs.attr}/bin/setfattr -n security.selinux -v system_u:object_r:root_t / 2>/dev/null || true
          paths="/etc /var /run /dev"
          for p in /home /opt /srv; do [ -d "$p" ] && paths="$paths $p"; done
          # shellcheck disable=SC2086
          ${pkgs.policycoreutils}/bin/setfiles -q -c "$pol" "$fc" $paths || true
        fi
      }

        relabel
    '';

  selinuxRelabelScript = pkgs.writeShellApplication {
    name = "selinux-relabel";
    runtimeInputs = [
      pkgs.policycoreutils
      pkgs.coreutils
      pkgs.attr
    ];
    text = selinuxRelabelSetup;
  };

in
{
  imports = [
    ./build.nix
    ./modules
    ./refpolicy.nix
  ];

  options.security.selinux = {
    enable = mkOption {
      type = types.bool;
      default = false;
      example = true;
      description = ''
        Whether to enable SELinux support via [SENix](https://github.com/Naxdy/SENix).
      '';
    };

    overlayPackages = mkOption {
      type = types.bool;
      default = true;
      example = false;
      description = ''
        Whether to add an overlay to nixpkgs that enables SELinux support for various packages.
      '';
    };

    policyVersion = mkOption {
      type = types.nullOr types.int;
      default = null;
      example = 33;
      description = ''
        The SELinux policy version to target when building policy modules.

        Passed to `semanage` via `policy-version` in `semanage.conf`. If `null`, the toolchain default is used.
      '';
    };

    modules = mkOption {
      type = types.attrsOf (
        types.submodule (
          { config, ... }:
          {
            options = {
              name = mkOption {
                type = types.str;
                readOnly = true;
                internal = true;
                default = config._module.args.name;
                description = ''
                  Name of this policy module, as referenced by `policy_module` in the module's type enforcement rules.

                  Defaults to the attribute name under `modules`.
                '';
              };
              layer = mkOption {
                type = types.str;
                default = "senix";
                example = "apps";
                description = ''
                  The "layer" this module is placed under.

                  Defaults to `senix` in order to not conflict with any existing layers / modules
                  within the refpolicy. If a layer + module combination already exists in the refpolicy,
                  options declared under `config.security.selinux.modules.*` take precedence.
                '';
              };
              interface = mkOption {
                type = types.nullOr (
                  types.oneOf [
                    types.pathInStore
                    types.str
                  ]
                );
                default = null;
                description = ''
                  Interface (`.if`) rules for this module, either as a Nix store path to a `.if` file
                  (accepted by `types.pathInStore`), or a raw string of the interface content.
                '';
              };
              typeEnforcement = mkOption {
                type = types.nullOr (
                  types.oneOf [
                    types.pathInStore
                    types.str
                  ]
                );
                default = null;
                description = ''
                  Type enforcement (`.te`) rules for this module, either as a Nix store path to a `.te` file
                  (accepted by `types.pathInStore`), or a raw string of the type enforcement content.
                '';
              };
              fileContext = mkOption {
                type = types.submodule {
                  options = {
                    source = mkOption {
                      type = types.nullOr types.pathInStore;
                      default = null;
                      description = ''
                        A Nix store path to a file context (`.fc`) file to use for this module directly,
                        instead of generating one from `rules`. Used when pulling a module verbatim from
                        the Reference Policy sources.
                      '';
                    };
                    storePaths = mkOption {
                      type = types.attrsOf (types.listOf types.pathInStore);
                      default = { };
                      description = ''
                        A list of Nix store paths to generate the appropriate file context rules for.

                        Any entry in `rules` containing `@attr@` will be replicated for each path listed here.
                      '';
                    };
                    rules = mkOption {
                      type = types.attrsOf types.str;
                      default = { };
                      example = {
                        "@my_app@/bin/my_app" = "gen_context(system_u:object_r:my_app_exec_t,s0)";
                        "HOME_DIR/\.cache/my_app(/.*)?" = "gen_context(system_u:object_r:my_app_cache_t,s0)";
                      };
                      description = ''
                        An attribute set of paths with their corresponding context assignments.

                        If a path begins with `@attr@`, that rule will be repeated for every path listed in `storePaths.<attr>`.
                      '';
                    };
                  };
                };
                default = { };
                description = ''
                  File context (`.fc`) rules for this module.
                '';
              };
            };
          }
        )
      );
      default = { };
      description = ''
        An attribute set of extra modules to include in the final policy.
      '';
    };

    type = mkOption {
      type = types.str;
      default = "refpolicy";
      example = "targeted";
      description = ''
        The SELinux policy type.
      '';
    };

    mode = mkOption {
      type = types.enum [
        "enforcing"
        "permissive"
        "disabled"
      ];
      default = "permissive";
      example = "enforcing";
      description = ''
        SELinux enforcement mode.
      '';
    };

  };

  config = lib.mkIf cfg.enable {
    nixpkgs.overlays = lib.mkForce (
      lib.optionals cfg.overlayPackages [
        (
          final: prev:
          let
            # Building `coreutils` with `selinuxSupport` in this nixpkgs revision trips the
            # bootstrap `fetchurlBoot` (it does not accept `nativeBuildInputs`). Drop it from
            # the override set until upstream can build SELinux-enabled coreutils during bootstrap.
            overridePkgs = [
              {
                name = "emacs";
                flag = "withSelinux";
              }
              {
                name = "systemd";
                flag = "withSelinux";
              }
              {
                name = "casync";
                flag = "selinuxSupport";
              }
              {
                name = "erofs-utils";
                flag = "selinuxSupport";
              }
              {
                name = "flatpak";
                flag = "withSELinuxModule";
              }
              {
                name = "postgresql";
                flag = "selinuxSupport";
              }
              {
                name = "postgresql_14";
                flag = "selinuxSupport";
              }
              {
                name = "postgresql_15";
                flag = "selinuxSupport";
              }
              {
                name = "postgresql_16";
                flag = "selinuxSupport";
              }
              {
                name = "postgresql_17";
                flag = "selinuxSupport";
              }
              {
                name = "postgresql_18";
                flag = "selinuxSupport";
              }
            ];
          in
          builtins.listToAttrs (
            map (
              {
                name,
                flag,
              }:
              {
                inherit name;
                value = prev.${name}.override {
                  ${flag} = true;
                };
              }
            ) overridePkgs
          )
        )
      ]
    );

    systemd.package = lib.mkDefault (
      pkgs.systemd.override {
        withSelinux = true;
      }
    );

    boot.kernelPatches = [
      {
        name = "selinux";
        structuredExtraConfig = with lib.kernel; {
          SECURITY_SELINUX = yes;
        };
        patch = null;
      }
    ];

    # The store overlay setup mounts the metadata SquashFS via a loop device, so
    # ensure the loop module is available as early as possible.
    boot.kernelModules = [
      "loop"
    ];

    # The store overlay activation mounts the metadata SquashFS via a loop device
    # from within the initrd (the activation scripts run there during boot), so
    # ensure the loop module is available to the initrd too.
    boot.initrd.kernelModules = [
      "loop"
    ];

    # `systemd` is PID 1 and must run as `init_t` (not `kernel_t`) to boot
    # directly into enforcing mode, but the store overlay/`semodule` (which
    # labels files) only runs in stage 2 — after PID 1 is exec'd. So load the
    # SELinux policy, label the systemd binary `init_exec_t`, and start
    # enforcing from within the initrd, before the real init is exec'd. Together
    # with the `type_transition ... -> init_t` in the `init_context` module this
    # makes systemd run as `init_t`.
    boot.initrd.systemd.storePaths = [
      pkgs.attr
      pkgs.policycoreutils
      pkgs.libselinux.bin
      cfg.build.policy
    ];
    # `semodule`/libsemanage hardcodes the HLL compiler dir and the external
    # `setfiles`/`load_policy`/`sefcontext_compile` commands to `/usr/libexec`
    # and `/sbin`/`/usr/sbin`, none of which exist in the read-only initrd.
    # Supply a `semanage.conf` that points them at the store paths, and use a
    # writable store under `/run` (the initrd `/var` is read-only).
    boot.initrd.systemd.contents."/etc/selinux/semanage.conf".text =
      lib.optionalString (cfg.policyVersion != null) ''
        policy-version = ${toString cfg.policyVersion}
      ''
      + ''
        store-root = /run/selinux
        compiler-directory = ${pkgs.policycoreutils}/libexec/selinux/hll

        [load_policy]
        path = ${pkgs.policycoreutils}/bin/load_policy
        [end]

        [setfiles]
        path = ${pkgs.policycoreutils}/bin/setfiles
        args = -q -c $@ $<
        [end]

        [sefcontext_compile]
        path = ${pkgs.libselinux.bin}/bin/sefcontext_compile
        args = $@
        [end]
      '';

    boot.initrd.systemd.services.selinux-init = {
      wantedBy = [ "initrd.target" ];
      path = [
        pkgs.policycoreutils
        pkgs.attr
        pkgs.findutils
        pkgs.coreutils
      ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        # The service runs before the policy is loaded, so request the
        # `init_unit_t` domain up front — it is granted the `associate` +
        # tool-transition accesses in the `selinux_tools` policy module.
        SELinuxContext = "system_u:system_r:init_unit_t";
      };
      script = ''
        # Install and link the policy modules, make the linked policy visible to
        # `load_policy` (which reads `/etc/selinux/<type>/policy/policy.<ver>`
        # and performs the kernel version conversion), then enforce. We cannot
        # rely on the store overlay here (it is not up yet, and the initrd store
        # cannot hold xattrs), so label the systemd binary `init_exec_t`
        # directly — both the initrd copy and the real-root copy mounted at
        # `/sysroot/nix/store`. That makes systemd's re-exec at switch_root
        # transition to `init_t` via the `init_context` type_transition, so PID 1
        # can start units in enforcing mode.
        pp=""
        for f in ${lib.escapeShellArg cfg.build.policy}/share/selinux/refpolicy/*.pp; do
          [ -e "$f" ] && pp="$pp $f"
        done
        ${pkgs.policycoreutils}/bin/semodule -s ${cfg.type} -i ''${pp}

        mkdir -p /etc/selinux/${cfg.type}/policy

        printf 'SELINUXTYPE=${cfg.type}\n' > /etc/selinux/config

        SRC=/run/selinux/${cfg.type}/active/policy.kern
        if [ -f "$SRC" ]; then
          for v in $(seq 40 25); do cp "$SRC" /etc/selinux/${cfg.type}/policy/policy.$v; done
        fi

        ${pkgs.policycoreutils}/bin/load_policy
        ${lib.optionalString (cfg.mode == "enforcing") "${lib.getExe' pkgs.libselinux.bin "setenforce"} 1"}

        # Label every store unit file `systemd_unit_t` before switch_root so the
        # real systemd can manage them for the boot window (otherwise systemd
        # cannot report/start units that are still `unlabeled_t`). `setfiles`
        # does not descend the `/nix/store` mount and `restorecon` has no
        # `/sysroot` alternate root, so we walk the unit paths with `find`+
        # `setfattr` — the same mechanism used for the systemd binary below,
        # which does persist. Only unit paths are touched to stay within the
        # initrd's memory; the immutable store only carries the labels in the
        # overlay upper, so it is never written to.
        ${pkgs.findutils}/bin/find /sysroot/nix/store \
          \( -path '*/systemd/system/*' -o -path '*/systemd/user/*' -o -path '*-unit-*/*' \) \
          \( -type f -o -type l \) \
          -exec ${pkgs.attr}/bin/setfattr -n security.selinux -v system_u:object_r:systemd_unit_t {} + \
          2>/dev/null || true

        SD=${config.systemd.package}/lib/systemd/systemd
        ${pkgs.attr}/bin/setfattr -n security.selinux -v system_u:object_r:init_exec_t "$SD" || true

        SRD=/sysroot/nix/store/$(basename ${config.systemd.package})/lib/systemd/systemd
        if [ -f "$SRD" ]; then
          ${pkgs.attr}/bin/setfattr -n security.selinux -v system_u:object_r:init_exec_t "$SRD" || true
        fi
      '';
    };

    security.lsm = [
      "selinux"
    ];

    system.activationScripts.selinux = {
      deps = [
        "etc"
      ];
      text =
        # bash
        ''
          install -d -m0755 /var/lib/selinux
          # The full policy (base + all declared modules) comes from
          # `build.policy`; it is installed wholesale.
          pp=""
          keep=""
          for f in ${lib.escapeShellArg cfg.build.policy}/share/selinux/refpolicy/*.pp; do
            if [ -e "$f" ]; then
              pp="$pp $f"
              keep="$keep $(basename "$f" .pp)"
            fi
          done
          cmd="${lib.getExe' pkgs.policycoreutils "semodule"} -s ${lib.escapeShellArg cfg.type} -i ''${pp}"
          skipSELinuxActivation=0

          if [ -f /var/lib/selinux/activate-check ]; then
            if [ "$(cat /var/lib/selinux/activate-check)" == "$cmd" ]; then
              skipSELinuxActivation=1
            fi
          fi

          if [ $skipSELinuxActivation -eq 0 ]; then
            eval "$cmd"
            # `semodule -i` installs/updates a module but never removes one that
            # is no longer part of the policy (e.g. a module dropped by a
            # rebuild/switch). Remove those stale modules so their types vanish
            # from the active policy and their store labels revert. Only touch
            # modules that were actually installed.
            if [ -n "$keep" ]; then
              # `semodule -i` installs/updates but never removes a module that is
              # no longer part of the policy (e.g. one dropped by a rebuild or
              # switch). Remove those stale modules so their types vanish from the
              # active policy and their store labels revert. `keep` lists the
              # module names from the current build; it is empty only where the
              # build store is unavailable (e.g. early initrd), in which case the
              # modules are the ones just installed, so there is nothing stale.
              for m in $(${lib.getExe' pkgs.policycoreutils "semodule"} -s ${lib.escapeShellArg cfg.type} -l 2>/dev/null | tr -d '\0\r'); do
                if ! echo " $keep " | grep -qw "$m"; then
                  ${lib.getExe' pkgs.policycoreutils "semodule"} -s ${lib.escapeShellArg cfg.type} -r "$m" || true
                fi
              done
            fi
            echo "$cmd" >/var/lib/selinux/activate-check
          fi
        '';
    };

    environment = {
      etc."selinux/config".text = ''
        SELINUX=${cfg.mode}
        SELINUXTYPE=${cfg.type}
      '';

      etc."selinux/semanage.conf".text =
        lib.optionalString (cfg.policyVersion != null) ''
          policy-version = ${toString cfg.policyVersion}
        ''
        + ''
          compiler-directory = ${pkgs.policycoreutils}/libexec/selinux/hll

          [load_policy]
          path = ${lib.getExe' pkgs.policycoreutils "load_policy"}
          [end]

          [setfiles]
          path = ${lib.getExe' pkgs.policycoreutils "setfiles"}
          args = -q -c $@ $<
          [end]

          [sefcontext_compile]
          path = ${lib.getExe' pkgs.libselinux "sefcontext_compile"}
          args = -r $@
          [end]
        '';

      systemPackages = [
        pkgs.libselinux
        pkgs.policycoreutils
        selinuxRelabelScript
      ];
    };

    # Apply the SELinux file-context labels at boot on the real root. This runs
    # after switch_root, because the store labels must land on the real
    # `/nix/store` (the initrd's store is discarded at switch_root) and the
    # `setfiles` needs the `file_contexts` generated by the initrd
    # `selinux-init` service's `semodule` (kept under `/run/selinux`). The Nix
    # store stays immutable: `setfiles` writes the labels onto the (writable)
    # overlay upper, not the store itself.
    systemd.services.selinux-relabel = {
      # Run during sysinit, before multi-user.target is confirmed, so the store
      # and the systemd unit files are labeled before systemd reports/controls
      # unit status. (The store overlay applies the policy file_contexts directly
      # via `setfiles` — no loop device / metadata image — so this can run this
      # early without needing the store's squashfs mount.)
      wantedBy = [ "sysinit.target" ];
      before = [ "multi-user.target" ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        # Run as `init_unit_t`, which is granted the `associate` + tool
        # transitions in the `selinux_tools` policy module.
        SELinuxContext = "system_u:system_r:init_unit_t";
      };
      script = ''
        ${selinuxRelabelScript}/bin/selinux-relabel
      '';
    };

    # A `nixos-rebuild switch` re-applies the labels for the new configuration.
    system.activationScripts.selinuxRelabel = {
      deps = [
        "etc"
      ];
      text = ''
        ${selinuxRelabelScript}/bin/selinux-relabel
      '';
    };
  };
}
