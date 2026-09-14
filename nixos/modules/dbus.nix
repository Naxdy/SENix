{
  config,
  lib,
  ...
}:
{
  config.security.selinux = {
    booleans = {
      dbus_broker_system_bus = lib.mkDefault true;
    };
    modules.dbus = {
      layer = "services";
      fileContext = {
        storePaths = {
          dbus = [
            config.services.dbus.dbusPackage
          ];
          dbus-broker = [
            config.services.dbus.brokerPackage
          ];
        };
        rules = {
          "HOME_DIR/\.dbus(/.*)?" = "gen_context(system_u:object_r:session_dbusd_home_t,s0)";

          "/etc/dbus-.*(/.*)?" = "gen_context(system_u:object_r:dbusd_etc_t,s0)";

          "/run/dbus(/.*)?" = "gen_context(system_u:object_r:system_dbusd_runtime_t,s0)";
          "/run/messagebus\.pid" = "--	gen_context(system_u:object_r:system_dbusd_runtime_t,s0)";
          "/run/user/%{USERID}/bus" = "-s	gen_context(system_u:object_r:session_dbusd_runtime_t,s0)";
          "/run/user/%{USERID}/dbus-1(/.*)?" = "gen_context(system_u:object_r:session_dbusd_runtime_t,s0)";

          "@dbus@/bin/dbus-daemon(-1)?" = "--	gen_context(system_u:object_r:dbusd_exec_t,s0)";

          # needed by dbus-broker
          "@dbus-broker@/bin/dbus-broker-launch" = "--	gen_context(system_u:object_r:dbusd_exec_t,s0)";
          "@dbus-broker@/bin/dbus-broker" = "--	gen_context(system_u:object_r:dbusd_exec_t,s0)";

          "@dbus@/lib/dbus-.*/dbus-daemon-launch-helper" =
            "--	gen_context(system_u:object_r:dbusd_exec_t,s0)";

          # Systemd unit file
          "@dbus-broker@/lib/systemd/system/[^/]*dbus.*" =
            "--	gen_context(system_u:object_r:dbusd_unit_t,s0)";

          "@dbus@/libexec/dbus-daemon-launch-helper" = "--	gen_context(system_u:object_r:dbusd_exec_t,s0)";

          "/var/lib/dbus(/.*)?" = "gen_context(system_u:object_r:system_dbusd_var_lib_t,s0)";

          # /var/run prefix exception; https://dbus.freedesktop.org/doc/dbus-specification.html#idm2461
          "/var/run/dbus/system_bus_socket" = "gen_context(system_u:object_r:system_dbusd_runtime_t,s0)";
        };
      };
    };
  };
}
