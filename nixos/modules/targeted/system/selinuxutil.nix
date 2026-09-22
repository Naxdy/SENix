{
  config,
  pkgs,
  ...
}:
{
  config.security.selinux.modules.selinuxutil = {
    fileContext = {
      storePaths = {
        selinux = [
          pkgs.policycoreutils
        ];
        # The NixOS-generated `/etc/selinux/config`. Its store path is matched
        # by the `usr_t` catch-all `corecommands` glob, but it is really a
        # SELinux config; label it `selinux_config_t` so `setfiles`/`restorecon`
        # (which can read that type) can relabel it without a special grant.
        selinux_config = [
          config.environment.etc."selinux/config".source
        ];
      };
      rules = {
        #
        # /etc
        "@selinux_config@(/.*)?" = "gen_context(system_u:object_r:selinux_config_t,s0)";

        #
        # @selinux@
        #
        "@selinux@/bin/checkpolicy" = "--	gen_context(system_u:object_r:checkpolicy_exec_t,s0)";
        "@selinux@/bin/load_policy" = "--	gen_context(system_u:object_r:load_policy_exec_t,s0)";
        "@selinux@/bin/newrole" = "--	gen_context(system_u:object_r:newrole_exec_t,s0)";
        "@selinux@/bin/restorecon" = "--	gen_context(system_u:object_r:setfiles_exec_t,s0)";
        "@selinux@/bin/run_init" = "--	gen_context(system_u:object_r:run_init_exec_t,s0)";
        "@selinux@/bin/setfiles.*" = "--	gen_context(system_u:object_r:setfiles_exec_t,s0)";
        "@selinux@/bin/setsebool" = "--	gen_context(system_u:object_r:semanage_exec_t,s0)";
        "@selinux@/bin/semanage" = "--	gen_context(system_u:object_r:semanage_exec_t,s0)";
        "@selinux@/bin/semodule" = "--	gen_context(system_u:object_r:semanage_exec_t,s0)";

        "@selinux@/share/system-config-selinux/selinux_server\.py" =
          "--	gen_context(system_u:object_r:selinux_dbus_exec_t,s0)";

        "@selinux@/libexec/selinux/semanage_migrate_store" =
          "--	gen_context(system_u:object_r:semanage_exec_t,s0)";

        "@selinux@/lib/selinux/semanage_migrate_store" =
          "--	gen_context(system_u:object_r:semanage_exec_t,s0)";
      };
    };
  };
}
