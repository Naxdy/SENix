{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib) mkOption types;

  cfg = config.security.selinux;

  setsebools = lib.escapeShellArgs (
    lib.mapAttrsToList (name: value: "${name}=${if value then "on" else "off"}") cfg.booleans
  );
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

    booleans = mkOption {
      type = types.submodule {
        freeformType = types.attrsOf types.bool;
      };
      default = { };
      defaultText = "Defaults are provided by various modules.";
      example = {
        dbus_broker_system_bus = true;
        dbus_can_network = true;
      };
      description = ''
        Booleans for consumption by tunable policies.

        This is used to the `booleans.local` file in `/etc/selinux/targeted`.
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

                  Note that the rule must start with a `<summary>` doc comment, or else the module
                  won't be included in the final policy.
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
                      apply = lib.mapAttrs (_: value: lib.unique value);
                    };
                    rules = mkOption {
                      type = types.attrsOf (
                        types.oneOf [
                          types.str
                          (types.listOf types.str)
                        ]
                      );
                      default = { };
                      example = {
                        "@my_app@/bin/my_app" = "gen_context(system_u:object_r:my_app_exec_t,s0)";
                        "HOME_DIR/\.cache/my_app(/.*)?" = "gen_context(system_u:object_r:my_app_cache_t,s0)";
                        "@my_app@/lib" = [
                          "-d gen_context(system_u:object_r:my_app_lib_t,s0)"
                          "-l gen_context(system_u:object_r:my_app_lib_t,s0)"
                        ];
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
    assertions = [
      {
        assertion = !lib.any (e: e == "ro") config.boot.nixStoreMountOpts;
        message = ''
          With SELinux enabled, the Nix store must not be mounted readonly.

          The Nix store is automatically remounted readonly at a later point in the boot process, when it is safe to do so.

          Please remove `ro` from the options declared in `config.boot.nixStoreMountOpts` or disable SELinux.
        '';
      }
      {
        assertion = !config.nix.settings.auto-optimise-store;
        message = ''
          `config.nix.settings.auto-optimise-store = true` conflicts with SELinux.

          Since hardlinks share the same inode, and xattrs that carry SELinux labels are attached to specific inodes,
          those two concepts are in direct opposition to one another.

          Though the MetaFS overlay guarantees each store path appears as a unique inode, and forwards link calls to
          the underlying filesystem, running optimisation after every Nix build is unnecessarily taxing.

          It is recommended to use filesystem-level deduplication instead, e.g. something like`config.services.beesd`
          for btrfs filesystems, or native ZFS deduplication.
        '';
      }
    ];

    # We use this to remove `ro` as the store mount option, since our overlay
    # already ensures the underlying store cannot be written to.
    boot.nixStoreMountOpts = lib.mkForce [ ];

    nixpkgs.overlays = lib.mkForce (
      lib.optionals cfg.overlayPackages [
        (
          final: prev:
          let
            # Building `coreutils` with `selinuxSupport` in this nixpkgs revision trips the
            # bootstrap `fetchurlBoot` (it does not accept `nativeBuildInputs`). Exclude it from
            # the override set until upstream can build SELinux-enabled coreutils during bootstrap.
            # Everything else can be overridden by default.
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
      etc = {
        "selinux/config".text = ''
          SELINUX=${cfg.mode}
          SELINUXTYPE=targeted
        '';

        "selinux/semanage.conf".text =
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
      };

      systemPackages = [
        pkgs.libselinux
        pkgs.policycoreutils
        pkgs.metafs
      ];
    };

    # Activates a policy on system boot (after initrd) and on switch.
    system.activationScripts = {
      selinux-policy = {
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
            cmd="${lib.getExe' pkgs.policycoreutils "semodule"} -s targeted -i ''${pp}"
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
                for m in $(${lib.getExe' pkgs.policycoreutils "semodule"} -s targeted -l 2>/dev/null | tr -d '\0\r'); do
                  if ! echo " $keep " | grep -qw "$m"; then
                    ${lib.getExe' pkgs.policycoreutils "semodule"} -s targeted -r "$m" || true
                  fi
                done
              fi

              ${lib.getExe' pkgs.policycoreutils "setsebool"} -P ${setsebools}

              echo "$cmd" >/var/lib/selinux/activate-check
            fi
          '';
      };

      # selinux-metafs = {
      #   deps = [
      #     "usrbinenv"
      #   ];
      #   text =
      #     # bash
      #     ''
      #       if ! cat /proc/self/mountinfo | grep -q metafs; then
      #         if [ ! -e /run/current-system ]; then
      #           mkdir -p /run/current-system/sw/bin
      #
      #           ln -sf "${lib.getExe' pkgs.metafs "mount.fuse.metafs"}" /run/current-system/sw/bin/mount.fuse.metafs
      #           echo "mounting metafs..."
      #           mount -t fuse.metafs /nix/store /nix/store
      #
      #           rm -rf /run/current-system
      #         else
      #           echo "mounting metafs..."
      #           mount -t fuse.metafs /nix/store /nix/store
      #         fi
      #       fi
      #     '';
      # };
    };

    boot.initrd.systemd = {
      storePaths = [
        pkgs.attr
        pkgs.policycoreutils
        pkgs.libselinux.bin
        pkgs.metafs
        cfg.build.policy
      ];

      # `semodule`/libsemanage hardcodes the HLL compiler dir and the external
      # `setfiles`/`load_policy`/`sefcontext_compile` commands to `/usr/libexec`
      # and `/sbin`/`/usr/sbin`, none of which exist in the read-only initrd.
      # Supply a `semanage.conf` that points them at the store paths, and use a
      # writable store under `/run` (the initrd `/var` is read-only).
      contents = {
        "/etc/selinux/semanage.conf".text =
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
      };

      services = {
        # Prepares the necessary prerequisites for mounting the metacopy overlay.
        selinux-init = {
          wantedBy = [ "initrd-fs.target" ];
          before = [ "initrd-fs.target" ];
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
          };
          unitConfig = {
            RequiresMountsFor = [
              "/sysroot/run"
              "/sysroot/nix/store"
            ];
          };
          script = ''
            set -euo pipefail

            sleep 1

            pp=""
            for f in ${lib.escapeShellArg cfg.build.policy}/share/selinux/refpolicy/*.pp; do
              [ -e "$f" ] && pp="$pp $f"
            done
            semodule -s targeted -i ''${pp}

            # semanage writes the store to `store-root` (`/run/selinux`) from
            # semanage.conf, but libselinux + setfiles/restorecon read the tree
            # `/etc/selinux/<type>/{policy, contexts/files}` (computed from
            # SELINUXTYPE), which the semanage store does not lay out. Link
            # `/etc/selinux/<type>` to the store and symlink the libselinux-visible
            # files to the store's `active/` artifacts, so `load_policy` and
            # `setfiles` find the linked policy and file contexts.
            rm -rf /etc/selinux/targeted
            ln -s /run/selinux/targeted /etc/selinux/targeted
            mkdir -p /etc/selinux/targeted/contexts/files /etc/selinux/targeted/policy
            ln -sfn ../../active/file_contexts /etc/selinux/targeted/contexts/files/file_contexts
            ln -sfn ../active/policy.kern /etc/selinux/targeted/policy/policy
            for v in $(seq 40 -1 25); do
              ln -sfn policy /etc/selinux/targeted/policy/policy.$v || true
            done

            # We let systemd handle all of the relabeling for us.
            mkdir -p /run/systemd/relabel-extra.d || true
            echo "/nix" >> /run/systemd/relabel-extra.d/10-senix.relabel
            echo "/nix/store" >> /run/systemd/relabel-extra.d/10-senix.relabel
            echo "/etc" >> /run/systemd/relabel-extra.d/10-senix.relabel
            echo "/var" >> /run/systemd/relabel-extra.d/10-senix.relabel
            echo "/home" >> /run/systemd/relabel-extra.d/10-senix.relabel
            echo "/usr" >> /run/systemd/relabel-extra.d/10-senix.relabel

            printf 'SELINUXTYPE=targeted\n' > /etc/selinux/config

            load_policy -i

            setsebool -P ${setsebools}

            fc=/etc/selinux/targeted/contexts/files/file_contexts

            echo "relabeling initrd..."

            # We need to relabel the initrd's nix store in order to
            # ensure that systemd's post-initrd transition to `init_t` works.
            setfiles -F "$fc" /nix/store
            setfiles -r /sysroot -F "$fc" /sysroot${config.systemd.package}
            setfiles -r /sysroot -F "$fc" /sysroot -e /sysroot/nix/store
          '';
        };

        selinux-metafs = {
          wantedBy = [ "selinux-init.service" ];
          before = [ "selinux-init.service" ];
          serviceConfig = {
            Type = "exec";
            # `--switch-root`: the overlay must survive the initrd root switch;
            # systemd itself relabels /nix/store immediately after the switch
            # (through this very overlay), so there is no chance to re-mount.
            # source == mountpoint here.
            ExecStart = "${lib.getExe pkgs.metafs} -f /sysroot/nix/store /sysroot/nix/store -o nosuid,nodev,fscontext=system_u:object_r:senix_meta_t:s0 --seclabel";
          };
          unitConfig = {
            DefaultDependencies = false;
            IgnoreOnIsolate = true;
            SurviveFinalKillSignal = true;
            RefuseManualStop = true;
            RequiresMountsFor = [
              "/sysroot/nix/store"
            ];
          };
        };
      };
    };

    systemd.services = {
      selinux-metafs-remount = {
        description = "Remount MetaFS Store";
        wantedBy = [
          "sysinit.target"
        ];
        before = [
          "sysinit.target"
          "shutdown.target"
          "nix-daemon.socket"
          "nix-daemon.service"
        ]
        ++ (lib.optional (
          config.systemd.services ? register-nix-paths
        ) config.systemd.services.register-nix-paths.name);
        after = [
          "local-fs.target"
        ];
        conflicts = [
          "shutdown.target"
        ];
        restartIfChanged = false;
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
        };
        unitConfig.DefaultDependencies = false;
        path = [
          pkgs.util-linux
        ];
        script = ''
          mount --bind /nix/store /nix/store

          mount -o remount,ro,bind /nix/store
        '';
      };

      selinux-metafs = {
        serviceConfig = {
          Type = "exec";
          ExecStart = "${lib.getExe pkgs.metafs} -f /nix/store /nix/store -o nosuid,nodev --seclabel";
        };
        restartIfChanged = false;
        unitConfig = {
          DefaultDependencies = false;
          IgnoreOnIsolate = true;
          SurviveFinalKillSignal = true;
          RefuseManualStop = true;
        };
      };
      # Runs on `nixos-rebuild switch` to relabel the nix store.
      # Here, we skip the userspace directories, because we don't want to
      # override any runtime changes a user may have made.
      #
      # TODO: Untested; need to confirm whether this works / gets called.
      # selinux-relabel = {
      #   wantedBy = [ "nixos-activation.service" ];
      #   after = [ "nixos-activation.service" ];
      #   serviceConfig = {
      #     Type = "oneshot";
      #     RemainAfterExit = true;
      #   };
      #   path = [
      #     pkgs.policycoreutils
      #   ];
      #   script = ''
      #     set -euo pipefail
      #
      #     fc=/etc/selinux/targeted/contexts/files/file_contexts
      #
      #     setfiles -F "$fc" /nix/store 2>&1
      #     find /nix/store -type f -o -type d -o -type l | setfiles -F "$fc" -s
      #   '';
      # };
    };
  };
}
