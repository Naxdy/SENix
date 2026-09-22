{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib) mkOption types;

  cfg = config.programs.bubblewrap;
in
{
  options.programs.bubblewrap = {
    enable = lib.mkEnableOption "bubblewrap sandboxing utility";

    package = lib.mkPackageOption pkgs "bubblewrap";

    selinuxSupport = mkOption {
      type = types.bool;
      default = config.security.selinux.enable;
      defaultText = lib.literalExpression "config.security.selinux.enable";
      description = ''
        Whether to add SELinux modules for this program.
      '';
    };
  };

  config = lib.mkIf cfg.enable (
    lib.mkMerge [
      {
        environment.systemPackages = [
          cfg.package
        ];
      }
      (lib.mkIf cfg.selinuxSupport {
        security.selinux.modules.bubblewrap = {
          layer = "apps";
          fileContext = {
            storePaths.bubblewrap = [
              cfg.package
            ];
            rules = {
              "@bubblewrap@/bin/bwrap" = "--	gen_context(system_u:object_r:bubblewrap_exec_t,s0)";
            };
          };
        };
      })
    ]
  );
}
