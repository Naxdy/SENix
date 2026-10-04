{
  config,
  lib,
  pkgs,
  ...
}:
{
  config = lib.mkIf config.services.nscd.enable {
    security.selinux.modules = {
      nscd = {
        typeEnforcement = ''
          gen_require(`
            type nscd_t;
            class process { getsched };
          ')

          allow nscd_t self:process getsched;
          kernel_read_net_sysctls(nscd_t);
        '';
        fileContext = {
          storePaths = {
            nscd = lib.optional (!config.services.nscd.enableNsncd) [
              config.services.nscd.package
            ];
            nsncd = lib.optional config.services.nscd.enableNsncd pkgs.nsncd;
          };
          rules = {
            "@nscd@/bin/nscd" = "--	gen_context(system_u:object_r:nscd_exec_t,s0)";
            "@nsncd@/bin/nsncd" = "--	gen_context(system_u:object_r:nscd_exec_t,s0)";
            "/run/nscd/socket" = "-s gen_context(system_u:object_r:nscd_runtime_t,s0)";
          };
        };
      };
    };
  };
}
