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

    policy = mkOption {
      type = types.path;
      default = "${
        pkgs.selinux-refpolicy.override { policyVersion = "refpolicy"; }
      }/share/selinux/refpolicy";
      defaultText = ''
        The refpolicy of `pkgs.selinux-refpolicy`.
      '';
      description = ''
        Path to the SELinux policy.
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
                default = config._module.args.name;
                description = ''
                  Name of this policy module, as referenced by `policy_module` in the module's type enforcement rules.

                  Defaults to the attribute name under `modules`.
                '';
              };
              interface = mkOption {
                type = types.nullOr types.str;
                default = null;
                description = ''
                  Interface (`.if`) rules for this module.
                '';
              };
              typeEnforcement = mkOption {
                type = types.nullOr types.str;
                default = null;
                description = ''
                  Type enforcement (`.te`) rules for this module.
                '';
              };
              fileContext = mkOption {
                type = types.submodule {
                  options = {
                    storePaths = mkOption {
                      type = types.attrsOf (types.listOf types.path);
                      default = [ ];
                      description = ''
                        A list of store paths to generate the appropriate file context rules for.

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
          cmd="${lib.getExe' pkgs.policycoreutils "semodule"} -s ${lib.escapeShellArg cfg.type} -i ${lib.escapeShellArg cfg.policy}/*.pp"
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
      ];
    };
  };
}
