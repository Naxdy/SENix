{ ... }:
{
  config,
  lib,
  pkgs,
  ...
}:
{
  config.security.selinux.modules.docportal =
    lib.mkIf (config.xdg.portal.enable && config.security.selinux.enable)
      {
        fileContext = {
          storePaths.desktop-portal = [
            pkgs.xdg-desktop-portal
          ];
          rules = {
            "@desktop-portal@/libexec/xdg-document-portal" =
              "-- gen_context(system_u:object_r:docportal_exec_t,s0)";
          };
        };
      };
}
