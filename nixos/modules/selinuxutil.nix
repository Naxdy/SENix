{
  config,
  pkgs,
  ...
}:
{
  config.security.selinux.modules.selinuxutil = {
    layer = "system";
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
        # SELinux userland utilities

        #
        # /etc
        #
        # The store path of the generated `/etc/selinux/config` (the catch-all
        # `usr_t` glob would otherwise label it). Only the file itself, not the
        # `/etc/selinux` tree (which is covered below).
        "@selinux_config@" = "gen_context(system_u:object_r:selinux_config_t,s0)";
        "/etc/selinux(/.*)?" = "gen_context(system_u:object_r:selinux_config_t,s0)";
        "/etc/selinux/([^/]*/)?contexts/files(/.*)?" = "gen_context(system_u:object_r:file_context_t,s0)";
        "/etc/selinux/([^/]*/)?policy(/.*)?" =
          "gen_context(system_u:object_r:policy_config_t,mls_systemhigh)";
        "/etc/selinux/([^/]*/)?setrans\.conf" =
          "--	gen_context(system_u:object_r:selinux_config_t,mls_systemhigh)";
        "/etc/selinux/([^/]*/)?seusers" =
          "--	gen_context(system_u:object_r:selinux_config_t,mls_systemhigh)";
        "/etc/selinux/([^/]*/)?modules(/.*)?" = "gen_context(system_u:object_r:semanage_store_t,s0)";
        "/etc/selinux/([^/]*/)?modules/semanage\.read\.LOCK" =
          "--	gen_context(system_u:object_r:semanage_read_lock_t,s0)";
        "/etc/selinux/([^/]*/)?modules/semanage\.trans\.LOCK" =
          "--	gen_context(system_u:object_r:semanage_trans_lock_t,s0)";
        "/etc/selinux/([^/]*/)?users(/.*)?" =
          "--	gen_context(system_u:object_r:selinux_config_t,mls_systemhigh)";

        #
        # /root
        #
        "/root/\.default_contexts" = "-- 	gen_context(system_u:object_r:default_context_t,s0)";

        #
        # /run
        #
        "/run/restorecond\.pid" = "--	gen_context(system_u:object_r:restorecond_run_t,s0)";

        "/run/selinux(/.*)?" = "gen_context(system_u:object_r:selinux_config_t,s0)";
        "/run/selinux/([^/]*/)?contexts(/.*)?" = "gen_context(system_u:object_r:default_context_t,s0)";
        "/run/selinux/([^/]*/)?contexts/files(/.*)?" = "gen_context(system_u:object_r:file_context_t,s0)";
        "/run/selinux/([^/]*/)?policy(/.*)?" =
          "gen_context(system_u:object_r:policy_config_t,mls_systemhigh)";
        "/run/selinux/([^/]*/)?setrans\.conf" =
          "--	gen_context(system_u:object_r:selinux_config_t,mls_systemhigh)";
        "/run/selinux/([^/]*/)?seusers" =
          "--	gen_context(system_u:object_r:selinux_config_t,mls_systemhigh)";
        "/run/selinux/([^/]*/)?modules(/.*)?" = "gen_context(system_u:object_r:semanage_store_t,s0)";
        "/run/selinux/([^/]*/)?modules/semanage\.read\.LOCK" =
          "--	gen_context(system_u:object_r:semanage_read_lock_t,s0)";
        "/run/selinux/([^/]*/)?modules/semanage\.trans\.LOCK" =
          "--	gen_context(system_u:object_r:semanage_trans_lock_t,s0)";
        "/run/selinux/([^/]*/)?users(/.*)?" =
          "--	gen_context(system_u:object_r:selinux_config_t,mls_systemhigh)";

        #
        # @selinux@
        #
        "@selinux@/bin/checkpolicy" = "--	gen_context(system_u:object_r:checkpolicy_exec_t,s0)";
        "@selinux@/bin/load_policy" = "--	gen_context(system_u:object_r:load_policy_exec_t,s0)";
        "@selinux@/bin/newrole" = "--	gen_context(system_u:object_r:newrole_exec_t,s0)";
        "@selinux@/bin/restorecon" = "--	gen_context(system_u:object_r:setfiles_exec_t,s0)";
        "@selinux@/bin/restorecond" = "--	gen_context(system_u:object_r:restorecond_exec_t,s0)";
        "@selinux@/bin/run_init" = "--	gen_context(system_u:object_r:run_init_exec_t,s0)";
        "@selinux@/bin/setfiles.*" = "--	gen_context(system_u:object_r:setfiles_exec_t,s0)";
        "@selinux@/bin/setsebool" = "--	gen_context(system_u:object_r:semanage_exec_t,s0)";
        "@selinux@/bin/semanage" = "--	gen_context(system_u:object_r:semanage_exec_t,s0)";
        "@selinux@/bin/semodule" = "--	gen_context(system_u:object_r:semanage_exec_t,s0)";

        "@selinux@/lib/systemd/system/restorecond.*\.service" =
          "--	gen_context(system_u:object_r:restorecond_unit_t,s0)";

        "@selinux@/share/system-config-selinux/selinux_server\.py" =
          "--	gen_context(system_u:object_r:selinux_dbus_exec_t,s0)";

        "@selinux@/libexec/selinux/semanage_migrate_store" =
          "--	gen_context(system_u:object_r:semanage_exec_t,s0)";

        #
        # /var/lib
        #
        "/var/lib/selinux(/.*)?" = "gen_context(system_u:object_r:semanage_store_t,s0)";
        "/var/lib/selinux/[^/]+/semanage\.read\.LOCK" =
          "--	gen_context(system_u:object_r:semanage_read_lock_t,s0)";
        "/var/lib/selinux/[^/]+/semanage\.trans\.LOCK" =
          "--	gen_context(system_u:object_r:semanage_trans_lock_t,s0)";
        "@selinux@/lib/selinux/semanage_migrate_store" =
          "--	gen_context(system_u:object_r:semanage_exec_t,s0)";
      };
    };
  };
}
