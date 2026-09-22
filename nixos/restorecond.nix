{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib) mkOption types;

  cfg = config.services.restorecond;

  defaultPaths = [
    "/etc/resolv.conf"
    "/nix/store"
    "/root/*"
    "/root/.ssh/*"
    "/run/utmp"
    "/var/log/wtmp"
  ];

  defaultUserPaths = [
    "~/*"
    "~/public_html/*"
    "~/.gnome2/*"
    "~/local/*"
    "~/.fonts/*"
    "~/.cache/*"
    "~/.config/*"
    "~/.local/share/*"
  ];
in
{
  options.services.restorecond = {
    enable = mkOption {
      type = types.bool;
      default = config.security.selinux.enable;
      defaultText = lib.literalExpression "config.security.selinux.enable";
      example = false;
      description = ''
        Whether to enable [`restorecond(8)`](https://www.man7.org/linux/man-pages/man8/restorecond.8.html) to automatically relabel select paths.
      '';
    };

    package = lib.mkPackageOption pkgs "restorecond" { };

    paths = lib.mkOption {
      type = types.listOf types.path;
      default = defaultPaths;
      example = [
        "/var"
      ];
      description = ''
        Paths to have `restorecond` watch for automatic relabeling.

        Note: It is recommended to always have this contain `/nix/store` to avoid unexpected behavior
        involving unlabeled files.
      '';
    };

    userPaths = lib.mkOption {
      type = types.listOf types.str;
      default = defaultUserPaths;
      example = [
        "~/.mozilla/*"
      ];
      description = ''
        Paths to have the `restorecond` user service watch for automatic relabeling.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    # We declare them as regular priority here, so other modules can
    # add paths to these without risking a user override clearing them all out.
    services.restorecond.paths = defaultPaths;
    services.restorecond.userPaths = defaultUserPaths;

    systemd.services.restorecond = {
      description = "Restorecon maintaining path file context";
      wantedBy = [
        "multi-user.target"
      ];
      unitConfig = {
        ConditionSecurity = "selinux";
        ConditionPathExists = "/etc/selinux/restorecond.conf";
      };
      serviceConfig = {
        Type = "simple";
        PrivateMounts = true;
      };
      script = ''
        ${lib.getExe' pkgs.util-linux "mount"} -o remount,rw,bind /nix/store

        exec ${lib.getExe cfg.package} -F
      '';
    };

    systemd.user.services.restorecond = {
      description = "Restorecon maintaining path file context (user service)";
      unitConfig = {
        ConditionSecurity = "selinux";
        ConditionPathExists = "/etc/selinux/restorecond_user.conf";
      };
      serviceConfig = {
        Type = "dbus";
        BusName = "org.selinux.Restorecond";
        ExecStart = "${lib.getExe cfg.package} -u";
      };
    };

    environment.etc = {
      "selinux/restorecond.conf".source = pkgs.writeText "restorecond.conf" (
        builtins.concatStringsSep "\n" cfg.paths
      );

      "selinux/restorecond_user.conf".source = pkgs.writeText "restorecond_user.conf" (
        builtins.concatStringsSep "\n" cfg.userPaths
      );
    };

    security.selinux = {
      exclusions.systemdUnits = [
        config.systemd.services.restorecond.name
      ];

      modules.selinuxutil = {
        typeEnforcement = ''
          # /etc/selinux/restorecond.conf is a symlink
          allow restorecond_t selinux_config_t:lnk_file watch;

          # `restorecond` relabels through `selinux_restorecon()`, whose libselinux
          # implementation probes `/proc` with `statfs()` (`probe_proc()` in
          # `selinux_restorecon.c`, deciding whether it may address files via
          # `/proc/self/fd`) — i.e. the filesystem-level `getattr`. The reference
          # policy grants exactly that to `run_init_t` in the same `selinuxutil.te`
          # (`kernel_getattr_proc()`), but not to `restorecond_t`; Fedora instead
          # gives `restorecond_t` the broad `fs_getattr_all_fs()`.
          kernel_getattr_proc(restorecond_t);
        '';
        fileContext = {
          storePaths = {
            restorecond = [
              cfg.package
            ];
            restorecond_unit = [
              config.systemd.units."${config.systemd.services.restorecond.name}".unit
            ];
          };
          rules = {
            "@restorecond_unit@(/.*)?" = "gen_context(system_u:object_r:restorecond_unit_t,s0)";
            "@restorecond@/bin/restorecond" = "--	gen_context(system_u:object_r:restorecond_exec_t,s0)";
          };
        };
      };
    };
  };
}
