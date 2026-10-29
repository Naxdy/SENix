{
  overlay,
}:
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

  # Recomputes the label of every store path from the active file contexts.
  #
  # The labels live in metafs' in-memory map, and the store is read-only for
  # everyone but the Nix daemon, so the relabel is delegated to a transient
  # systemd unit: `PrivateMounts=` gives it a private mount namespace in which
  # the store can be remounted writable, leaving every other process with the
  # read-only overlay.
  storeRelabel = pkgs.writeShellScript "senix-store-relabel" ''
    ${lib.getExe' pkgs.util-linux "mount"} -o remount,rw,bind /nix/store
    exec ${lib.getExe' pkgs.policycoreutils "setfiles"} -F \
      /etc/selinux/targeted/contexts/files/file_contexts /nix/store
  '';
in
{
  imports = [
    ./build.nix
    ./modules
    ./refpolicy.nix
    ./restorecond.nix
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

    postBuildRelabel = mkOption {
      type = types.bool;
      default = true;
      example = false;
      description = ''
        Whether to add a post build hook that relabels store paths whenever a derivation is built.

        For automatic relabling of other directories, see `config.services.restorecond`.
      '';
    };

    exclusions = {
      etc = lib.mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [
          "selinux/restorecond.conf"
        ];
        description = ''
          Attribute names of `config.environment.etc` to not include in the automatic relabeling to `etc_t`.

          You should only need to add entries to this if you encounter issues with infinite recursion.
        '';
        apply = lib.unique;
      };
      systemdUnits = lib.mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [
          "restorecond.service"
        ];
        description = ''
          Attribute names of `config.systemd.units` to not include in the automatic relabeling to `systemd_unit_t`.

          You should only need to add entries to this if you encounter issues with infinite recursion.
        '';
        apply = lib.unique;
      };
      systemdPackages = lib.mkOption {
        type = types.listOf types.package;
        default = [ ];
        description = ''
          Packages containing systemd units to not include in the automatic relabeling to `systemd_unit_t.`

          You should only need to add entries to this if you encounter issues with infinite recursion.
        '';
      };
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
                  types.submodule {
                    options = {
                      summary = mkOption {
                        type = types.str;
                        example = ''
                          Policy for kernel threads, proc filesystem,
                          and unlabeled processes and objects.
                        '';
                        description = ''
                          Summary description of this module, for the generated docs.
                        '';
                      };
                      desc = mkOption {
                        type = types.nullOr types.lines;
                        default = null;
                        example = ''
                          <p>
                            Policy for kernel threads, proc filesystem,
                            and unlabeled processes and objects.
                          </p>
                        '';
                        description = ''
                          Long-form description of this module, for the generated docs.

                          Contents are XML fragments (e.g. `<p>...</p>`), placed inside the
                          module's `<desc>` element.
                        '';
                      };

                      required = mkOption {
                        type = types.nullOr types.str;
                        default = null;
                        example = ''
                          This module has initial SIDs.
                        '';
                        description = ''
                          Setting this to anything other than `null` marks this module as "required",
                          with the reason provided by this option.
                        '';
                      };

                      exports = mkOption {
                        type = types.attrsOf (
                          types.submodule {
                            options = {
                              type = mkOption {
                                type = types.enum [
                                  "interface"
                                  "template"
                                ];
                                default = "interface";
                                example = "template";
                                description = ''
                                  The kind of exported macro this entry is.

                                  One module can export both `interface(...)` and
                                  `template(...)` macros, so the kind is declared per entry.
                                '';
                              };
                              summary = mkOption {
                                type = types.str;
                                example = ''
                                  Allows the kernel to start userland processes
                                  by dynamic transitions to the specified domain.
                                '';
                                description = ''
                                  Summary description of this interface, for the generated docs.
                                '';
                              };
                              desc = mkOption {
                                type = types.nullOr types.lines;
                                default = null;
                                example = ''
                                  <p>
                                    Allows the kernel to start userland processes
                                    by dynamic transitions to the specified domain.
                                  </p>
                                '';
                                description = ''
                                  Long-form description of this interface, for the generated docs.

                                  Contents are XML fragments (e.g. `<p>...</p>`), placed inside
                                  the interface's `<desc>` element.
                                '';
                              };

                              params = mkOption {
                                type = types.attrsOf (
                                  types.submodule {
                                    options = {
                                      name = mkOption {
                                        type = types.str;
                                        description = ''
                                          The symbolic name of this parameter, as used in the docs.
                                        '';
                                      };
                                      description = mkOption {
                                        type = types.str;
                                        description = ''
                                          The description of this parameter.
                                        '';
                                      };
                                      optional = mkOption {
                                        type = types.bool;
                                        default = false;
                                        description = ''
                                          Whether this parameter is optional.
                                        '';
                                      };
                                      unused = mkOption {
                                        type = types.bool;
                                        default = false;
                                        description = ''
                                          Whether the interface does not actually use this parameter.
                                        '';
                                      };
                                    };
                                  }
                                );
                                default = { };
                                example = lib.literalExpression ''
                                  {
                                    "$1" = {
                                      name = "domain";
                                      description ="The process type entered by the kernel.";
                                    };
                                  }
                                '';
                                description = ''
                                  An attribute set of parameters this interface supports.

                                  Attribute names are the variable names used within the interface body, following the schema of `$n`
                                  where `n` is a nonzero positive integer incrementing with parameter count.
                                '';
                              };

                              gen_require = mkOption {
                                type = types.nullOr types.lines;
                                default = null;
                                example = ''
                                  type kernel_t;
                                '';
                                description = ''
                                  Contents of the `gen_require` block at the start of this interface.
                                '';
                              };

                              content = mkOption {
                                type = types.lines;
                                example = ''
                                  domain_dyntrans_type(kernel_t)
                                  allow kernel_t self:process setcurrent;
                                  allow kernel_t $1:process dyntransition;
                                '';
                                description = ''
                                  Main body contents of this interface.
                                '';
                              };

                              infoflow = mkOption {
                                type = types.nullOr (
                                  types.submodule {
                                    options = {
                                      type = mkOption {
                                        type = types.enum [
                                          "none"
                                          "read"
                                          "write"
                                          "both"
                                        ];
                                        description = ''
                                          The direction of information flow this interface grants.
                                        '';
                                      };
                                      weight = mkOption {
                                        type = types.nullOr (
                                          types.enum [
                                            "1"
                                            "2"
                                            "3"
                                            "4"
                                            "5"
                                            "6"
                                            "7"
                                            "8"
                                            "9"
                                            "10"
                                          ]
                                        );
                                        default = null;
                                        description = ''
                                          The weight of this information flow, for the generated docs.

                                          The docs DTD allows 1..10.
                                        '';
                                      };
                                    };
                                  }
                                );
                                default = null;
                                description = ''
                                  Information flow of this interface, for the generated docs.

                                  Declared as `<infoflow type="…" weight="…"/>`; a `none` flow has
                                  no weight.
                                '';
                              };

                              # The docs XML distinguishes interfaces whose content touches a
                              # role (`rolecap`) or that declare a role base (`rolebase`).
                              rolecap = mkOption {
                                type = types.bool;
                                default = false;
                                description = ''
                                  Whether this interface grants a role capability.
                                '';
                              };
                              rolebase = mkOption {
                                type = types.bool;
                                default = false;
                                description = ''
                                  Whether this interface declares a role base.
                                '';
                              };
                            };
                          }
                        );
                        default = { };
                        description = ''
                          Interfaces / macros exported by this module.

                          Attribute names are the names of the individual interfaces.
                        '';
                      };
                    };
                  }
                );
                default = null;
                description = ''
                  Exported macros / (`.if`) declarations for this module, with their documentation.

                  The module summary must be provided, or else the module won't be included in
                  the final policy; `sedoctool.py` registers a module in `modules.conf` only when
                  its XML documentation carries a `<summary>`. The interface entries are
                  themselves documented through `summary`, `desc` and `params`.
                '';
              };
              typeEnforcement = mkOption {
                type = types.nullOr types.lines;
                default = null;
                description = ''
                  Type enforcement (`.te`) rules for this module.
                '';
              };
              fileContext = mkOption {
                type = types.submodule {
                  options = {
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

    # `metafs` is a FUSE filesystem, and the kernel's FUSE implementation emits
    # no `fsnotify` events, so an inotify-based daemon (`restorecond`) can never
    # observe a store path Nix adds at runtime. Label the outputs of every build
    # here instead.
    #
    # Nix runs the hook after `restoreProcessContext()`, i.e. back in the
    # caller's mount namespace, where `/nix/store` is still read-only. So the
    # relabel is delegated to a transient systemd unit: `PrivateMounts=` gives it
    # a private mount namespace, in which the store can be remounted writable
    # (`LocalStore::makeStoreWritable()` does the same for the daemon).
    # `restorecon` then writes the contexts through the overlay, so they live in
    # metafs' in-memory map like every other label.
    nix.settings.post-build-hook =
      let
        relabelStorePath = pkgs.writeShellScript "senix-relabel-store-path" ''
          ${lib.getExe' pkgs.util-linux "mount"} -o remount,rw,bind /nix/store
          exec ${lib.getExe' pkgs.policycoreutils "restorecon"} -R "$1"
        '';
      in
      lib.mkIf cfg.postBuildRelabel (
        "${pkgs.writeShellScript "senix-post-build-hook" ''
          for out in ''${OUT_PATHS:-}; do
            ${lib.getExe' pkgs.systemd "systemd-run"} --quiet --collect --wait \
              --unit="senix-store-relabel-$$-$RANDOM" \
              --property=PrivateMounts=yes \
              --property=Type=oneshot \
              ${relabelStorePath} "$out"
          done
        ''}"
      );

    nixpkgs.overlays =
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
          // {
            # OpenSSH has no SELinux toggle in this nixpkgs revision; wire the
            # upstream support directly so sshd performs the standard
            # login-context transition (`get_default_context` ->
            # `default_contexts`), placing root's ssh sessions in
            # `sysadm_r:sysadm_t` instead of leaving every session stuck in
            # `sshd_t`.
            openssh = prev.openssh.overrideAttrs (old: {
              buildInputs = (old.buildInputs or [ ]) ++ [ final.libselinux ];
              configureFlags = (old.configureFlags or [ ]) ++ [ "--with-selinux" ];
            });
          }
        )
      ]
      ++ [
        overlay
      ];

    systemd.package = lib.mkDefault (
      pkgs.systemd.override {
        withSelinux = true;
      }
    );

    # `pam_selinux` is the PAM module that sets the session's default exec
    # context from the policy's `default_contexts`. The user manager relies on
    # it: `system_r:init_t` is mapped to the per-role manager domain
    # (`user_systemd_t` for `user_u`), so PAM's `open` call is what enters the
    # domain before `systemd --user` execs. nixpkgs builds linux-pam with
    # `-Dselinux=disabled`, which drops `pam_selinux.so` entirely — the
    # Fedora stack carries `pam_selinux.so close`/`nottys open` in
    # `systemd-user` for exactly this transition.
    security.pam.package = lib.mkDefault (
      pkgs.linux-pam.overrideAttrs (old: {
        buildInputs = (old.buildInputs or [ ]) ++ [ pkgs.libselinux ];
        # `pam_sepermit`'s lock dir is compiled from `localstatedir`; keep the
        # runtime path `/run/sepermit`, but install the empty dir relative to
        # the prefix (meson's `install_emptydir()` would otherwise write it
        # into the build sandbox's absolute `/var`).
        mesonFlags = lib.filter (flag: flag != "-Dselinux=disabled") (old.mesonFlags or [ ]) ++ [
          "-Dselinux=enabled"
          "-Dlocalstatedir=/run"
        ];
        postPatch = (old.postPatch or "") + ''
          substituteInPlace modules/module-meson.build \
            --replace-fail "sepermit_lockdir," "'run/sepermit',"
        '';
      })
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

        # Appconfig for the login-context machinery: SELinux-aware login
        # programs (`sshd` via `get_default_context`) read the
        # user→SELinux-user mapping (`seusers`), the context orderings
        # (`default_contexts`, `contexts/users/*`) and the role→type
        # defaults (`default_type`) from `/etc/selinux/<type>`. The
        # initrd provisions `/etc/selinux` in its ephemeral rootfs only,
        # so link these into the live tree on every activation (plain
        # store-path references; these files are immutable policy
        # artifacts, never customized per machine). Without them
        # `ssh_selinux_getctxbyname` fails and every ssh session dies in
        # enforcing mode.
        "selinux/targeted/seusers".source = "${cfg.build.policy}/etc/selinux/refpolicy/seusers";
        "selinux/targeted/contexts/default_contexts".source =
          "${cfg.build.policy}/etc/selinux/refpolicy/contexts/default_contexts";
        "selinux/targeted/contexts/default_type".source =
          "${cfg.build.policy}/etc/selinux/refpolicy/contexts/default_type";
        "selinux/targeted/contexts/failsafe_context".source =
          "${cfg.build.policy}/etc/selinux/refpolicy/contexts/failsafe_context";
        "selinux/targeted/contexts/users".source = "${cfg.build.policy}/selinux/refpolicy/contexts/users";
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

              # Booting already relabels the store from the initrd, so this is
              # only needed while a running system changes its policy, i.e. on
              # `switch-to-configuration` (which exports `NIXOS_ACTION`).
              if [ -n "''${NIXOS_ACTION:-}" ]; then
                ${lib.getExe' pkgs.systemd "systemd-run"} --quiet --collect --wait \
                  --unit="senix-store-relabel-$$" \
                  --property=PrivateMounts=yes \
                  --property=Type=oneshot \
                  ${storeRelabel}
              fi

              echo "$cmd" >/var/lib/selinux/activate-check
            fi
          '';
      };
    };

    security.selinux.exclusions.systemdUnits = [
      config.boot.initrd.systemd.services.selinux-init.name
    ];

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
            pkgs.libselinux.bin
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
            setfiles -r /sysroot -F "$fc" /sysroot${config.boot.kernelPackages.kernel.modules}
            setfiles -r /sysroot -F "$fc" /sysroot -e /sysroot/nix/store

            echo "seeding cgroup labels..."

            # `setfiles`/`restorecon` (and systemd's `label_fix()`) only write a
            # label when it differs from the one that is already there, and for
            # the cgroup tree the file contexts assign exactly the context the
            # kernel computes from `genfscon cgroup2` (`cgroup_t`), so nothing
            # ever stores a label on a cgroup node. The kernel needs one to
            # derive the labels of nodes it creates later
            # (`security_kernfs_init_security()` gives up without it), which is
            # what the policy's cgroup file transitions rely on — e.g.
            # `memory.pressure` becoming `memory_pressure_t`. Write the labels
            # unconditionally to seed the tree.
            find /sys/fs/cgroup -xdev -print0 | while IFS= read -r -d "" path; do
              raw=$(matchpathcon -n "$path" 2>/dev/null) || continue
              label=''${raw##* }
              [ -n "$label" ] || continue
              setfattr -n security.selinux -v "$label" "$path" || true
            done
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

      # `SurviveFinalKillSignal` requires a "companion unit" for the service
      # to survive post switchr-root. This is never meant to be run by itself.
      #
      # The value for `ExecStart` doesn't actually matter, but for consistency's
      # sake it's nice to have it be the same as the initrd one.
      selinux-metafs = {
        serviceConfig = {
          inherit (config.boot.initrd.systemd.services.selinux-metafs.serviceConfig)
            ExecStart
            Type
            ;
        };
        restartIfChanged = false;
        unitConfig = builtins.removeAttrs config.boot.initrd.systemd.services.selinux-metafs.unitConfig [
          "RequiresMountsFor"
        ];
      };

      senix-run-relabel = {
        description = "Relabel current-system";

        requiredBy = [ "sysinit-reactivation.target" ];
        partOf = [ "sysinit-reactivation.target" ];
        before = [ "systemd-tmpfiles-resetup.service" ];

        unitConfig.DefaultDependencies = false;
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
        };
        path = [ pkgs.policycoreutils ];
        script = ''
          setfiles -F /etc/selinux/targeted/contexts/files/file_contexts /run/current-system
        '';
      };
    };

    # The `systemd-user` PAM stack is what places `systemd --user` into its
    # per-role manager domain: `pam_selinux.so nottys open` computes the
    # default exec context from `/etc/selinux/<type>/contexts`, whose
    # `system_r:init_t` entry maps to e.g. `user_u:user_r:user_systemd_t`.
    # Fedora's stack (`systemd-user`) carries the same close/open pair, placed
    # ahead of the session modules; `close` restores the caller's context, and
    # `open` sets the exec context for the manager the service execs next.
    security.pam.services.systemd-user.rules.session = {
      selinux-close = {
        # Relative orders; NixOS's generated source rules start at 10100.
        order = config.security.pam.services.systemd-user.rules.session.env.order - 100;
        control = "required";
        modulePath = "${config.security.pam.package}/lib/security/pam_selinux.so";
        args = [ "close" ];
      };
      selinux-open = {
        order = config.security.pam.services.systemd-user.rules.session.env.order - 50;
        control = "required";
        modulePath = "${config.security.pam.package}/lib/security/pam_selinux.so";
        args = [
          "nottys"
          "open"
        ];
      };
    };
  };
}
