{ config, ... }: {
  config.security.selinux.modules.logging = {
    layer = "system";
    fileContext = {
      storePaths = {
        systemd = [
          config.systemd.package
          config.boot.initrd.systemd.package
        ];
      };
      rules = {
        "@systemd@/lib/systemd/system/auditd.*" = "-- gen_context(system_u:object_r:auditd_unit_t,s0)";
        "@systemd@/lib/systemd/system/[^/]*systemd-journal.*" =
          "-- gen_context(system_u:object_r:syslogd_unit_t,s0)";
        "@systemd@/lib/systemd/system/rsyslog.*\.service" =
          "-- gen_context(system_u:object_r:syslogd_unit_t,s0)";
        "@systemd@/lib/systemd/systemd-journald" = "-- gen_context(system_u:object_r:syslogd_exec_t,s0)";
        "@systemd@/lib/systemd/systemd-kmsg-syslogd" =
          "--	gen_context(system_u:object_r:syslogd_exec_t,s0)";
      };
    };
  };
}
