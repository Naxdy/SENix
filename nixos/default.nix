{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib) mkOption types;

  cfg = config.security.selinux;
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

    security.lsm = [
      "selinux"
    ];

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
      ];
    };

    # Activates a policy on system boot (after initrd) and on switch.
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

    boot.initrd.systemd = {
      # `systemd` is PID 1 and must run as `init_t` (not `kernel_t`) to boot
      # directly into enforcing mode, but the store overlay/`semodule` (which
      # labels files) only runs in stage 2 — after PID 1 is exec'd. So load the
      # SELinux policy, label the systemd binary `init_exec_t`, and start
      # enforcing from within the initrd, before the real init is exec'd. Together
      # with the `type_transition ... -> init_t` in the `init_context` module this
      # makes systemd run as `init_t`.
      storePaths = [
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
      contents."/etc/selinux/semanage.conf".text =
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

      # TODO: unsure if this propagates past the initrd phase; Need to test:
      # - does the metacopy overlay persist?
      # - when doing `nix build`, are new paths visible?
      # - when changing xattrs, are the underlying files affected? (should be NO)
      mounts = [
        {
          where = "/sysroot/nix/store";
          what = "overlay";
          type = "overlay";
          options = lib.concatStringsSep "," [
            "lowerdir=/sysroot/nix/.ro-store"
            "upperdir=/run/selinux/overlay/upper"
            "workdir=/run/selinux/overlay/work"
            "metacopy=on"
          ];
          unitConfig = {
            DefaultDependencies = false;
            RequiresMountsFor = [
              "/sysroot/nix/.ro-store"
            ];
          };
          requiredBy = [ "initrd-fs.target" ];
          after = [
            config.boot.initrd.systemd.services.selinux-init.name
          ];
        }
      ];

      services = {
        # Prepares the necessary prerequisites for mounting the metacopy overlay.
        init-selinux-overlay = {
          requiredBy = [ "initrd-fs.target" ];
          before = [
            "initrd-fs.target"
            "shutdown.target"
          ];
          conflicts = [ "shutdown.target" ];
          serviceConfig = {
            Type = "oneshot";
            RemainAfterExit = true;
          };
          script = ''
            set -uo pipefail
            export PATH="/bin:${
              lib.makeBinPath [
                pkgs.util-linux
              ]
            }"

            upper=/run/selinux/overlay
            store=/run/selinux/store

            mkdir -p /run/selinux "$upper" "$store"
            mount -t tmpfs -o size=64m,mode=0755 tmpfs "$upper" 2>/dev/null || true
            mkdir -p "$upper/upper" "$upper/work"
          '';
        };

        selinux-init = {
          wantedBy = [ "initrd.target" ];
          path = [
            pkgs.policycoreutils
            pkgs.attr
            pkgs.findutils
            pkgs.coreutils
            pkgs.mount
            pkgs.gnugrep
            pkgs.gnused
          ];
          serviceConfig = {
            Type = "oneshot";
            RemainAfterExit = true;
            # The service runs before the policy is loaded, so request the
            # `init_unit_t` domain up front — it is granted the `associate` +
            # tool-transition accesses in the `selinux_tools` policy module.
            SELinuxContext = "system_u:system_r:init_unit_t";
          };
          unitConfig = {
            RequiresMountsFor = [
              "/sysroot/run"
            ];
          };
          script = ''
            set -euo pipefail

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

            # semanage writes the store to `store-root` (`/run/selinux`) from
            # semanage.conf, but libselinux + setfiles/restorecon read the tree
            # `/etc/selinux/<type>/{policy, contexts/files}` (computed from
            # SELINUXTYPE), which the semanage store does not lay out. Link
            # `/etc/selinux/<type>` to the store and symlink the libselinux-visible
            # files to the store's `active/` artifacts, so `load_policy` and
            # `setfiles` find the linked policy and file contexts.
            rm -rf /etc/selinux/${cfg.type}
            ln -s /run/selinux/${cfg.type} /etc/selinux/${cfg.type}
            mkdir -p /etc/selinux/${cfg.type}/contexts/files /etc/selinux/${cfg.type}/policy
            ln -sfn ../../active/file_contexts /etc/selinux/${cfg.type}/contexts/files/file_contexts
            ln -sfn ../active/policy.kern /etc/selinux/${cfg.type}/policy/policy
            for v in $(seq 40 -1 25); do
              ln -sfn policy /etc/selinux/${cfg.type}/policy/policy.$v || true
            done

            printf 'SELINUXTYPE=${cfg.type}\n' > /etc/selinux/config

            ${pkgs.policycoreutils}/bin/load_policy
          '';
        };

        # The initrd relabel sets the correct labels on `/nix/store` (the initrd's nix store)
        # and on `/sysroot/nix/store` (the proper system nix store).
        #
        # The `/sysroot/nix/store` is mounted via a metacopy overlay in `config.boot.initrd.systemd.mounts`,
        # which propagates past the initrd phase.
        selinux-relabel = {
          wantedBy = [ "initrd.target" ];
          after = [
            config.boot.initrd.systemd.services.selinux-init.name
          ];
          serviceConfig = {
            Type = "oneshot";
            # The service runs before the policy is loaded, so request the
            # `init_unit_t` domain up front — it is granted the `associate` +
            # tool-transition accesses in the `selinux_tools` policy module.
            SELinuxContext = "system_u:system_r:init_unit_t";
          };
          path = [
            pkgs.policycoreutils
            pkgs.libselinux.bin
            pkgs.findutils
          ];
          script = ''
            set -euo pipefail

            fc=/etc/selinux/${cfg.type}/contexts/files/file_contexts

            # Run `setfiles` on the main store directory first, which causes it to walk all subdirs
            # and assign the correct permissions. This skips files however, so we run another
            # pass over all regular files afterwards.
            ${lib.getExe' pkgs.policycoreutils "setfiles"} -F "$fc" /nix/store 2>&1

            ${lib.getExe' pkgs.policycoreutils "setfiles"} -r /sysroot -F "$fc" /sysroot/nix/store
            find /sysroot/nix/store -type f -o -type d | ${lib.getExe' pkgs.policycoreutils "setfiles"} -r /sysroot -F "$fc" -s

            ${lib.optionalString (cfg.mode == "enforcing") "${lib.getExe' pkgs.libselinux.bin "setenforce"} 1"}
          '';
        };
      };
    };

    systemd.services = {
      # Relabel userspace directories on boot.
      # We skip `/nix/store` here because it's labeled during the initrd phase.
      #
      # TODO: untested
      selinux-relabel-init = {
        wantedBy = [ "sysinit.target" ];
        before = [ "multi-user.target" ];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          SELinuxContext = "system_u:system_r:init_unit_t";
        };
        script = ''
          echo "relabel userspace"
          ${pkgs.findutils}/bin/find /etc/selinux
          set -euo pipefail

          fc=/etc/selinux/${cfg.type}/contexts/files/file_contexts

          paths="/etc /var /run /dev"
          for p in /home /opt /srv; do [ -d "$p" ] && paths="$paths $p"; done
          # shellcheck disable=SC2086
          ${pkgs.policycoreutils}/bin/setfiles -F -q "$fc" $paths || true
        '';
      };

      # Runs on `nixos-rebuild switch` to relabel the nix store.
      # Here, we skip the userspace directories, because we don't want to
      # override any runtime changes a user may have made.
      #
      # TODO: unstested
      selinux-relabel = {
        wantedBy = [ "nixos-activation.service" ];
        after = [ "nixos-activation.service" ];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          SELinuxContext = "system_u:system_r:init_unit_t";
        };
        script = ''
          echo "relabel switch"
          set -euo pipefail

          fc=/etc/selinux/${cfg.type}/contexts/files/file_contexts

          ${lib.getExe' pkgs.policycoreutils "setfiles"} -F "$fc" /nix/store 2>&1
          find /nix/store -type f | ${lib.getExe' pkgs.policycoreutils "setfiles"} -F "$fc" -s
        '';
      };
    };

  };
}
