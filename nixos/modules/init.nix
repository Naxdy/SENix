{ config, lib, ... }:
let
  # Units are labeled `systemd_unit_t` by the catch-all below unless another
  # module claims them: our own `selinux*` services belong to `systemd.nix`, and
  # a module can opt a unit out via `security.selinux.exclusions.systemdUnits`
  # (e.g. `restorecond.nix`, which labels its unit `restorecond_unit_t`
  # instead). Two modules assigning different types to the same unit store path
  # is a conflicting file context rule, which `semodule` rejects outright.
  claims =
    name:
    !(lib.hasInfix "selinux" name) && !(lib.elem name config.security.selinux.exclusions.systemdUnits);
in
{
  # Based on the refpolicy's policy/modules/system/init.fc
  config.security.selinux.modules.init = {
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
              lib.filterAttrs (name: _: claims name) config.boot.initrd.systemd.units
            )
          ))
          ++ (lib.filter lib.isDerivation (
            lib.mapAttrsToList (_: value: value.unit) (
              lib.filterAttrs (name: _: claims name) config.systemd.units
            )
          ))
        );
        tmpfiles = config.systemd.tmpfiles.packages;
      };
      rules = {
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

        "@systemd@/libexec/dcc/start-.*" = "--	gen_context(system_u:object_r:initrc_exec_t,s0)";
        "@systemd@/libexec/dcc/stop-.*" = "--	gen_context(system_u:object_r:initrc_exec_t,s0)";

        "@units@(/.*)?" = "gen_context(system_u:object_r:systemd_unit_t,s0)";
        "@packages@/lib/systemd/system(/.*)?" = "gen_context(system_u:object_r:systemd_unit_t,s0)";

        "@tmpfiles@/lib/tmpfiles\\.d(/.*)?" = "gen_context(system_u:object_r:systemd_tmpfiles_conf_t,s0)";
        "@systemd@/example/tmpfiles\\.d(/.*)?" =
          "gen_context(system_u:object_r:systemd_tmpfiles_conf_t,s0)";
      };
    };
  };
}
