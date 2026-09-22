{ config, lib, ... }:
let
  inherit (lib) mkOption types;
  cfg = config.services.fail2ban;
in
{
  options.services.fail2ban.selinuxSupport = mkOption {
    type = types.bool;
    default = config.security.selinux.enable;
    defaultText = lib.literalExpression "config.security.selinux.enable";
    description = ''
      Whether to add SELinux modules for this program.
    '';
  };

  config = lib.mkIf (cfg.enable && cfg.selinuxSupport) {
    security.selinux.modules.fail2ban.fileContext = {
      storePaths.fail2ban = [
        cfg.package
      ];
      rules = {
        "@fail2ban@/bin/fail2ban" = "-- gen_context(system_u:object_r:fail2ban_exec_t,s0)";
        "@fail2ban@/bin/fail2ban-client" = "-- gen_context(system_u:object_r:fail2ban_client_exec_t,s0)";
        "@fail2ban@/bin/fail2ban-server" = "-- gen_context(system_u:object_r:fail2ban_exec_t,s0)";
      };
    };
  };
}
