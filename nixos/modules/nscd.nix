{
  config,
  lib,
  ...
}:
{
  config = lib.mkIf config.services.nscd.enable {
    security.selinux.modules = {
      nscd = {
        layer = "services";
        fileContext = {
          storePaths = {
            nscd = [
              config.services.nscd.package
            ];
          };
          rules = {
            "/etc/rc\.d/init\.d/nscd" = "--	gen_context(system_u:object_r:nscd_initrc_exec_t,s0)";

            "@nscd@/bin/nscd" = "--	gen_context(system_u:object_r:nscd_exec_t,s0)";

            "/var/cache/nscd(/.*)?" = "gen_context(system_u:object_r:nscd_runtime_t,s0)";

            "/var/db/nscd(/.*)?" = "gen_context(system_u:object_r:nscd_runtime_t,s0)";

            "/var/log/nscd\.log.*" = "--	gen_context(system_u:object_r:nscd_log_t,s0)";

            "/run/nscd(/.*)?" = "gen_context(system_u:object_r:nscd_runtime_t,s0)";
            "/run/nscd\.pid" = "--	gen_context(system_u:object_r:nscd_runtime_t,s0)";
            "/run/\.nscd_socket" = "-s	gen_context(system_u:object_r:nscd_runtime_t,s0)";
          };
        };
      };
      nscd_extra = {
        layer = "services";
        typeEnforcement = ''
          policy_module(nscd_extra)

          gen_require(`
            type nscd_t;
            class process { getsched };
          ')

          allow nscd_t self:process getsched;
          kernel_use_fds(nscd_t);
        '';
      };
    };
  };
}
