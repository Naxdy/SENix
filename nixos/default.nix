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

    modules = mkOption {
      type = types.attrsOf (
        types.submodule {
          options = {
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
                  rules = {
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
      );
      default = { };
      description = ''
        An attribute set of extra modules to include in the final policy.
      '';
    };

    type = {
      type = types.str;
      default = "refpolicy";
      example = "targeted";
      description = ''
        The SELinux policy type.
      '';
    };

    mode = {
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
    nixpkgs.overlays = [
      (
        final: prev:
        let
          overridePkgs = [
            "casync"
            "celeste64"
            "coreutils"
            "emacs"
            "erofs-utils"
            "esdm"
            "flatpak"
            "postgresql"
            "postgresql_14"
            "postgresql_15"
            "postgresql_16"
            "postgresql_17"
            "postgresql_18"
            "systemd"
          ];
        in
        builtins.listToAttrs (
          map (name: {
            inherit name;
            value = prev.${name}.override {
              withSelinux = true;
            };
          }) overridePkgs
        )
      )
    ];

    boot.kernelPatches = [
      {
        name = "selinux";
        extraStructuredConfig = with lib.kernel; {
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
