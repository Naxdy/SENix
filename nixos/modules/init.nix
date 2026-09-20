{ config, lib, ... }: {
  # Based on the refpolicy's policy/modules/system/init.fc
  config.security.selinux.modules.init = {
    layer = "system";
    fileContext = {
      storePaths = {
        systemd = [
          config.systemd.package
          config.boot.initrd.systemd.package
        ];
        packages = lib.unique (config.systemd.packages ++ config.boot.initrd.systemd.packages);
        units = lib.unique (
          (lib.filter lib.isDerivation (
            lib.mapAttrsToList (_: value: value.unit) (
              lib.filterAttrs (
                name: _:
                # need to exclude our own services to avoid infinite recursion
                !(lib.hasInfix "selinux" name)
              ) config.boot.initrd.systemd.units
            )
          ))
          ++ (lib.filter lib.isDerivation (
            lib.mapAttrsToList (_: value: value.unit) (
              lib.filterAttrs (name: _: !(lib.hasInfix "selinux" name)) config.systemd.units
            )
          ))
        );
        tmpfiles = config.systemd.tmpfiles.packages;
      };
      rules = {
        #
        # /etc
        #
        "/etc/rc\.d/rc" = "--	gen_context(system_u:object_r:initrc_exec_t,s0)";
        "/etc/rc\.d/rc\.[^/]+" = "--	gen_context(system_u:object_r:initrc_exec_t,s0)";

        "/etc/rc\.d/init\.d/.*" = "--	gen_context(system_u:object_r:initrc_exec_t,s0)";
        "/etc/sysconfig/network-scripts/ifup-ipsec" = "-- gen_context(system_u:object_r:initrc_exec_t,s0)";

        "/etc/X11/prefdm" = "--	gen_context(system_u:object_r:initrc_exec_t,s0)";

        #
        # /dev
        #
        "/dev/initctl" = "-p	gen_context(system_u:object_r:initctl_t,s0)";

        #
        # /etc
        #
        "/etc/containers/systemd(/.*)?" = "gen_context(system_u:object_r:systemd_unit_t,s0)";

        #
        # /usr
        #
        "@systemd@/bin/init(ng)?" = "--	gen_context(system_u:object_r:init_exec_t,s0)";
        "@systemd@/bin/open_init_pty" = "--	gen_context(system_u:object_r:initrc_exec_t,s0)";
        "@systemd@/bin/sepg_ctl" = "--	gen_context(system_u:object_r:initrc_exec_t,s0)";
        "@systemd@/bin/systemd" = "--	gen_context(system_u:object_r:init_exec_t,s0)";
        "@systemd@/bin/upstart" = "--	gen_context(system_u:object_r:init_exec_t,s0)";

        "@systemd@/lib/dracut/modules\.d/[^/]+/.*\.service" =
          "--	gen_context(system_u:object_r:systemd_unit_t,s0)";
        "@systemd@/lib/systemd/systemd" = "-- gen_context(system_u:object_r:init_exec_t,s0)";
        "@systemd@/lib/systemd/systemd-executor" = "--	gen_context(system_u:object_r:init_exec_t,s0)";
        "@systemd@/lib/systemd/systemd-shutdown" = "--	gen_context(system_u:object_r:init_exec_t,s0)";
        "@systemd@/lib/systemd/systemd-oomd" = "--	gen_context(system_u:object_r:init_exec_t,s0)";
        "@systemd@/lib/systemd/system-preset(/.*)?" = "gen_context(system_u:object_r:systemd_unit_t,s0)";
        "@systemd@/lib/systemd/user-preset(/.*)?" = "gen_context(system_u:object_r:systemd_unit_t,s0)";
        "@systemd@/lib/systemd/ntp-units\\.d" = "-d gen_context(system_u:object_r:systemd_unit_t,s0)";
        "@systemd@/(lib|example|share)/systemd/(system|user)(/.*)?" =
          "gen_context(system_u:object_r:systemd_unit_t,s0)";
        "@systemd@/share/containers/systemd(/.*)?" = "gen_context(system_u:object_r:systemd_unit_t,s0)";
        "@systemd@/example/tmpfiles\\.d(/.*)?" =
          "gen_context(system_u:object_r:systemd_tmpfiles_conf_t,s0)";
        "@tmpfiles@/lib/tmpfiles\\.d(/.*)?" = "gen_context(system_u:object_r:systemd_tmpfiles_conf_t,s0)";

        "/run/systemd/generator(/.*)?" = "gen_context(system_u:object_r:systemd_unit_t,s0)";
        "/run/systemd/generator\.early(/.*)?" = "gen_context(system_u:object_r:systemd_unit_t,s0)";
        "/run/systemd/generator\.late(/.*)?" = "gen_context(system_u:object_r:systemd_unit_t,s0)";
        "/run/systemd/system(/.*)?" = "gen_context(system_u:object_r:systemd_unit_t,s0)";
        "/run/systemd/units(/.*)?" = "gen_context(system_u:object_r:systemd_unit_t,s0)";
        "/run/systemd/transient(/.*)?" = "gen_context(system_u:object_r:systemd_transient_unit_t,s0)";

        "@systemd@/libexec/dcc/start-.*" = "--	gen_context(system_u:object_r:initrc_exec_t,s0)";
        "@systemd@/libexec/dcc/stop-.*" = "--	gen_context(system_u:object_r:initrc_exec_t,s0)";

        "@units@/[^/]+" = "gen_context(system_u:object_r:systemd_unit_t,s0)";
        "@packages@/lib/systemd/system(/.*)?" = "gen_context(system_u:object_r:systemd_unit_t,s0)";

        #
        # /var
        #
        "/var/lib/random-seed" = "--	gen_context(system_u:object_r:init_random_seed_t,s0)";
        "/var/lib/systemd(/.*)?" = "gen_context(system_u:object_r:init_var_lib_t,s0)";

        "/run/initctl" = "-p	gen_context(system_u:object_r:initctl_t,s0)";
        "/run/kerneloops\.pid" = "--	gen_context(system_u:object_r:initrc_runtime_t,s0)";
        "/run/utmp" = "--	gen_context(system_u:object_r:initrc_runtime_t,s0)";
        "/run/runlevel\.dir" = "gen_context(system_u:object_r:initrc_runtime_t,s0)";
        "/run/random-seed" = "--	gen_context(system_u:object_r:init_random_seed_t,s0)";
        "/run/setmixer_flag" = "--	gen_context(system_u:object_r:initrc_runtime_t,s0)";
        "/run/systemd(/.*)?" = "gen_context(system_u:object_r:init_runtime_t,s0)";
        "/run/wd_keepalive\.pid" = "--	gen_context(system_u:object_r:initrc_runtime_t,s0)";
      };
    };
  };
}
