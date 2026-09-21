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
        };
      };
    };
  };
}
