{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib) mkOption types;

  cfg = config.security.selinux;

  # The single store-overlay setup. It is packaged as `selinux-store-overlay`
  # (see `storeOverlayScript`) and run by the activation script at boot and on
  # `nixos-rebuild switch`. It is idempotent: it only mounts the overlay once
  # (never re-mounting over the store's own overlayfs), and on re-runs it skips
  # work entirely unless `build.squashfs` changed, in which case it refreshes the
  # metadata image and re-applies the baked labels.
  storeOverlaySetup =
    # bash
    ''
      set -eu

      setupStoreOverlay() {
        upper=/run/selinux/overlay
        meta=/run/selinux/metadata
        store=/run/selinux/store

        # Skip entirely if the same squashfs is already active — e.g. a switch
        # that didn't change any referenced store paths (no new labels to apply).
        if [ -e /run/selinux/overlay-active ] &&
           [ "$(cat /run/selinux/store-overlay-squashfs 2>/dev/null)" = "${cfg.build.squashfs}" ]; then
          return 0
        fi

        if [ ! -e /run/selinux/overlay-active ]; then
          # Fresh setup (boot). The overlay itself is only mounted here; the Nix
          # store (itself already an overlayfs) must not be stacked further on
          # later re-runs, so we never unmount /nix/store once set up.
          mkdir -p /run/selinux "$upper" "$meta" "$store"
          mount -t tmpfs -o size=64m,mode=0755 tmpfs "$upper"
          mkdir -p "$upper/upper" "$upper/work"
          # The real store, exposed as the lower layer so every store path (past,
          # present, or added at runtime with nix build) stays visible with data.
          mount --bind /nix/store "$store"
          # Overlay the metadata over the store: a writable tmpfs upper carries the
          # labels (via metacopy) while file data continues to come from the store.
          mount -t overlay overlay \
            -o "lowerdir=$store,upperdir=$upper/upper,workdir=$upper/work,metacopy=on" \
            /nix/store
          # Mark as set up so later re-runs (e.g. a switch) only refresh labels and
          # never re-mount the overlay (which would push overlayfs past its max
          # stacking depth).
          touch /run/selinux/overlay-active
        fi

        # Refresh the metadata image with the (possibly different) build.squashfs.
        # If the loop device isn't available yet (e.g. very early initrd), defer;
        # a later run (switch or the loop device coming up) will retry.
        umount "$meta" 2>/dev/null || true
        if ! mount -t squashfs -o ro,loop ${cfg.build.squashfs} "$meta" 2>/dev/null; then
          return 0
        fi

        # Copy the baked `security.selinux` labels from the metadata image onto the
        # overlaid store paths. `setfattr` triggers metadata-only copy-up, so labels
        # land in the tmpfs upper; data stays in the store.
        find "$meta" -mindepth 1 \( -type f -o -type l -o -type d \) | while IFS= read -r f; do
          if ctx=$(getfattr -n security.selinux --only-values "$f" 2>/dev/null); then
            rel=''${f#"$meta"}
            setfattr -n security.selinux -v "$ctx" "/nix/store$rel"
          fi
        done

        # Record which squashfs is currently mounted so idempotent re-runs can
        # skip work when nothing changed.
        echo "${cfg.build.squashfs}" > /run/selinux/store-overlay-squashfs
      }

        setupStoreOverlay
    '';

  # A single, re-runnable overlay setup. The activation script (boot + switch)
  # runs this; exposing it as a package also lets a `nixos-rebuild switch` (and
  # the test) trigger a re-apply by invoking it, so there is only one place that
  # holds the setup logic.
  storeOverlayScript = pkgs.writeShellApplication {
    name = "selinux-store-overlay";
    runtimeInputs = [
      pkgs.util-linux
      pkgs.coreutils
      pkgs.attr
      pkgs.findutils
    ];
    text = storeOverlaySetup;
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
    storeOverlay = mkOption {
      type = types.bool;
      default = true;
      description = ''
        Whether to overlay the SquashFS metadata filesystem built into `security.selinux.build.squashfs` over `/nix/store` at runtime.

        Files in the Nix store cannot carry setuid bits or extended attributes, so SELinux file context metadata has to be supplied externally. When enabled, the metadata is presented through a read-only overlay; when disabled, labels must instead come from path-based file context rules (e.g. via `modules.*.fileContext`).
      '';
    };

  };

  config = lib.mkIf cfg.enable {
    nixpkgs.overlays = [
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
    ];

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
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
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
          for f in ${lib.escapeShellArg cfg.build.policy}/share/selinux/refpolicy/*.pp; do
            [ -e "$f" ] && pp="$pp $f"
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
        storeOverlayScript
      ];
    };

    system.activationScripts.selinuxStoreOverlay = lib.mkIf cfg.storeOverlay {
      deps = [
        "etc"
      ];
      text = ''
        ${storeOverlayScript}/bin/selinux-store-overlay
      '';
    };
  };
}
