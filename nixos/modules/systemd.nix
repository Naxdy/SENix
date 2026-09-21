{ config, lib, ... }: {
  # `systemd-tmpfiles` owns a good part of NixOS's writable tree: `/var`,
  # `/nix/var` (the Nix daemon's state), `/root`, `/lib64`, `/srv` and friends
  # are all created from tmpfiles rules, and on a fresh system they do not
  # exist yet. The reference policy keeps the permissions for that behind this
  # tunable — default off, `gen_tunable(systemd_tmpfiles_manage_all, false)`
  # in `systemd.te` — under which `systemd_tmpfiles_t` may manage objects of
  # every non-security file type. Without it tmpfiles is limited to the types
  # it knows about, so every path outside those is denied: `/nix/var` in the
  # `usr_t`-labelled `/nix`, `/root` in `root_t`, `/lib64` and `/srv` in
  # `root_t`, the chown of the `/run/keys` ramfs root, …
  config.security.selinux.booleans.systemd_tmpfiles_manage_all = lib.mkDefault true;

  # Based on the refpolicy's policy/modules/system/systemd.fc
  config.security.selinux.modules = {
    systemd = {
      layer = "system";
      fileContext = {
        storePaths = {
          systemd =
            builtins.filter (e: !(lib.any (o: e == o) config.security.selinux.exclusions.systemdPackages))
              [
                config.systemd.package
              ];
          # packages providing systemd units and hooks
          units = lib.unique (
            config.systemd.packages
            ++ (lib.filter lib.isDerivation (
              lib.mapAttrsToList (_: value: value.unit) (
                lib.filterAttrs (name: _: lib.hasInfix "selinux" name) config.systemd.units
              )
            ))
          );
        };
        rules = {
          "@systemd@/bin/journalctl" = "--	gen_context(system_u:object_r:systemd_journalctl_exec_t,s0)";
          "@systemd@/bin/systemd-analyze" = "--	gen_context(system_u:object_r:systemd_analyze_exec_t,s0)";
          "@systemd@/bin/systemd-cgtop" = "--	gen_context(system_u:object_r:systemd_cgtop_exec_t,s0)";
          "@systemd@/bin/systemd-coredump" = "--	gen_context(system_u:object_r:systemd_coredump_exec_t,s0)";
          "@systemd@/bin/systemd-hwdb" = "--	gen_context(system_u:object_r:systemd_hw_exec_t,s0)";
          "@systemd@/bin/systemd-machine-id-setup" =
            "--	gen_context(system_u:object_r:systemd_machine_id_setup_exec_t,s0)";
          "@systemd@/bin/systemd-nspawn" = "--	gen_context(system_u:object_r:systemd_nspawn_exec_t,s0)";
          "@systemd@/bin/systemd-stdio-bridge" =
            "--	gen_context(system_u:object_r:systemd_stdio_bridge_exec_t,s0)";
          "@systemd@/bin/systemd-sysusers" = "--	gen_context(system_u:object_r:systemd_sysusers_exec_t,s0)";
          "@systemd@/bin/systemd-tmpfiles" = "--	gen_context(system_u:object_r:systemd_tmpfiles_exec_t,s0)";
          "@systemd@/bin/systemd-tty-ask-password-agent" =
            "--	gen_context(system_u:object_r:systemd_passwd_agent_exec_t,s0)";
          "@systemd@/bin/systemd-notify" = "--	gen_context(system_u:object_r:systemd_notify_exec_t,s0)";

          # Systemd generators
          "@systemd@/lib/systemd/system-environment-generators/.*" =
            "--	gen_context(system_u:object_r:systemd_generator_exec_t,s0)";
          "@systemd@/lib/systemd/system-generators/.*" =
            "--	gen_context(system_u:object_r:systemd_generator_exec_t,s0)";
          "@systemd@/lib/systemd/user-environment-generators/.*" =
            "--	gen_context(system_u:object_r:systemd_generator_exec_t,s0)";
          "@systemd@/lib/systemd/user-generators/.*" =
            "--	gen_context(system_u:object_r:systemd_generator_exec_t,s0)";
          "@systemd@/libexec/podman/quadlet" =
            "--	gen_context(system_u:object_r:systemd_generator_exec_t,s0)";

          "@systemd@/lib/systemd/systemd-activate" =
            "--	gen_context(system_u:object_r:systemd_activate_exec_t,s0)";
          "@systemd@/lib/systemd/systemd-backlight" =
            "--	gen_context(system_u:object_r:systemd_backlight_exec_t,s0)";
          "@systemd@/lib/systemd/systemd-binfmt" =
            "--	gen_context(system_u:object_r:systemd_binfmt_exec_t,s0)";
          "@systemd@/lib/systemd/systemd-cgroups-agent" =
            "--	gen_context(system_u:object_r:systemd_cgroups_exec_t,s0)";
          "@systemd@/lib/systemd/systemd-coredump" =
            "--	gen_context(system_u:object_r:systemd_coredump_exec_t,s0)";
          "@systemd@/lib/systemd/systemd-homed" = "--	gen_context(system_u:object_r:systemd_homed_exec_t,s0)";
          "@systemd@/lib/systemd/systemd-homework" =
            "-- gen_context(system_u:object_r:systemd_homework_exec_t,s0)";
          "@systemd@/lib/systemd/systemd-hostnamed" =
            "--	gen_context(system_u:object_r:systemd_hostnamed_exec_t,s0)";
          "@systemd@/lib/systemd/systemd-localed" =
            "--	gen_context(system_u:object_r:systemd_locale_exec_t,s0)";
          "@systemd@/lib/systemd/systemd-logind" =
            "--	gen_context(system_u:object_r:systemd_logind_exec_t,s0)";
          "@systemd@/lib/systemd/systemd-machined" =
            "--	gen_context(system_u:object_r:systemd_machined_exec_t,s0)";
          "@systemd@/lib/systemd/systemd-modules-load" =
            "--	gen_context(system_u:object_r:systemd_modules_load_exec_t,s0)";
          "@systemd@/lib/systemd/systemd-networkd" =
            "--	gen_context(system_u:object_r:systemd_networkd_exec_t,s0)";
          "@systemd@/lib/systemd/systemd-network-generator" =
            "--	gen_context(system_u:object_r:systemd_networkd_exec_t,s0)";
          "@systemd@/lib/systemd/systemd-nsresourced" =
            "--	gen_context(system_u:object_r:systemd_nsresourced_exec_t,s0)";
          "@systemd@/lib/systemd/systemd-nsresourcework" =
            "--	gen_context(system_u:object_r:systemd_nsresourced_exec_t,s0)";
          "@systemd@/lib/systemd/systemd-pcrextend" =
            "--	gen_context(system_u:object_r:systemd_pcrphase_exec_t,s0)";
          "@systemd@/lib/systemd/systemd-pcrlock" =
            "--	gen_context(system_u:object_r:systemd_pcrphase_exec_t,s0)";
          "@systemd@/lib/systemd/systemd-pcrphase" =
            "--	gen_context(system_u:object_r:systemd_pcrphase_exec_t,s0)";
          "@systemd@/lib/systemd/systemd-pstore" =
            "--	gen_context(system_u:object_r:systemd_pstore_exec_t,s0)";
          "@systemd@/lib/systemd/systemd-resolved" =
            "--	gen_context(system_u:object_r:systemd_resolved_exec_t,s0)";
          "@systemd@/lib/systemd/systemd-rfkill" =
            "--	gen_context(system_u:object_r:systemd_rfkill_exec_t,s0)";
          "@systemd@/lib/systemd/systemd-socket-proxyd" =
            "--	gen_context(system_u:object_r:systemd_socket_proxyd_exec_t,s0)";
          "@systemd@/lib/systemd/systemd-sysctl" =
            "--	gen_context(system_u:object_r:systemd_sysctl_exec_t,s0)";
          "@systemd@/lib/systemd/systemd-tpm2-setup" =
            "--	gen_context(system_u:object_r:systemd_pcrphase_exec_t,s0)";
          "@systemd@/lib/systemd/systemd-update-done" =
            "--	gen_context(system_u:object_r:systemd_update_done_exec_t,s0)";
          "@systemd@/lib/systemd/systemd-user-runtime-dir" =
            "--	gen_context(system_u:object_r:systemd_user_runtime_dir_exec_t,s0)";
          "@systemd@/lib/systemd/systemd-user-sessions" =
            "--	gen_context(system_u:object_r:systemd_sessions_exec_t,s0)";
          "@systemd@/lib/systemd/systemd-userdbd" =
            "--	gen_context(system_u:object_r:systemd_userdbd_exec_t,s0)";
          "@systemd@/lib/systemd/systemd-userwork" =
            "--	gen_context(system_u:object_r:systemd_userdbd_exec_t,s0)";

          "@systemd@/lib/systemd/user(/.*)?" = "gen_context(system_u:object_r:systemd_user_unit_t,s0)";

          "@systemd@/lib/systemd/system/[^/]*halt.*" = "--	gen_context(system_u:object_r:power_unit_t,s0)";
          "@systemd@/lib/systemd/system/[^/]*hibernate.*" =
            "--	gen_context(system_u:object_r:power_unit_t,s0)";
          "@systemd@/lib/systemd/system/[^/]*power.*" = "--	gen_context(system_u:object_r:power_unit_t,s0)";
          "@systemd@/lib/systemd/system/[^/]*reboot.*" = "--	gen_context(system_u:object_r:power_unit_t,s0)";
          "@systemd@/lib/systemd/system/[^/]*shutdown.*" =
            "--	gen_context(system_u:object_r:power_unit_t,s0)";
          "@systemd@/lib/systemd/system/[^/]*sleep.*" = "--	gen_context(system_u:object_r:power_unit_t,s0)";
          "@systemd@/lib/systemd/system/[^/]*suspend.*" = "--	gen_context(system_u:object_r:power_unit_t,s0)";
          "@systemd@/lib/systemd/system/systemd-backlight.*" =
            "--	gen_context(system_u:object_r:systemd_backlight_unit_t,s0)";
          "@systemd@/lib/systemd/system/systemd-binfmt.*" =
            "--	gen_context(system_u:object_r:systemd_binfmt_unit_t,s0)";
          "@systemd@/lib/systemd/system/systemd-networkd.*" =
            "gen_context(system_u:object_r:systemd_networkd_unit_t,s0)";
          "@systemd@/lib/systemd/system/systemd-network-generator.*" =
            "gen_context(system_u:object_r:systemd_networkd_unit_t,s0)";
          "@systemd@/lib/systemd/system/systemd-rfkill.*" =
            "--	gen_context(system_u:object_r:systemd_rfkill_unit_t,s0)";
          "@systemd@/lib/systemd/system/systemd-socket-proxyd\.service" =
            "--	gen_context(system_u:object_r:systemd_socket_proxyd_unit_file_t,s0)";
          "@systemd@/lib/systemd/system/systemd-userdbd\.(service|socket)" =
            "--	gen_context(system_u:object_r:systemd_userdbd_unit_t,s0)";
          "@systemd@/lib/systemd/system/user@\.service" =
            "--	gen_context(system_u:object_r:systemd_user_manager_unit_t,s0)";

          "@units@/lib/systemd/user(/.*)?" = "gen_context(system_u:object_r:systemd_user_unit_t,s0)";

          "@units@/lib/systemd/system/[^/]*halt.*" = "--	gen_context(system_u:object_r:power_unit_t,s0)";
          "@units@/lib/systemd/system/[^/]*hibernate.*" = "--	gen_context(system_u:object_r:power_unit_t,s0)";
          "@units@/lib/systemd/system/[^/]*power.*" = "--	gen_context(system_u:object_r:power_unit_t,s0)";
          "@units@/lib/systemd/system/[^/]*reboot.*" = "--	gen_context(system_u:object_r:power_unit_t,s0)";
          "@units@/lib/systemd/system/[^/]*shutdown.*" = "--	gen_context(system_u:object_r:power_unit_t,s0)";
          "@units@/lib/systemd/system/[^/]*sleep.*" = "--	gen_context(system_u:object_r:power_unit_t,s0)";
          "@units@/lib/systemd/system/[^/]*suspend.*" = "--	gen_context(system_u:object_r:power_unit_t,s0)";
          "@units@/lib/systemd/system/systemd-backlight.*" =
            "--	gen_context(system_u:object_r:systemd_backlight_unit_t,s0)";
          "@units@/lib/systemd/system/systemd-binfmt.*" =
            "--	gen_context(system_u:object_r:systemd_binfmt_unit_t,s0)";
          "@units@/lib/systemd/system/systemd-networkd.*" =
            "gen_context(system_u:object_r:systemd_networkd_unit_t,s0)";
          "@units@/lib/systemd/system/systemd-network-generator.*" =
            "gen_context(system_u:object_r:systemd_networkd_unit_t,s0)";
          "@units@/lib/systemd/system/systemd-rfkill.*" =
            "--	gen_context(system_u:object_r:systemd_rfkill_unit_t,s0)";
          "@units@/lib/systemd/system/systemd-socket-proxyd\.service" =
            "--	gen_context(system_u:object_r:systemd_socket_proxyd_unit_file_t,s0)";
          "@units@/lib/systemd/system/systemd-userdbd\.(service|socket)" =
            "--	gen_context(system_u:object_r:systemd_userdbd_unit_t,s0)";
          "@units@/lib/systemd/system/user@\.service" =
            "--	gen_context(system_u:object_r:systemd_user_manager_unit_t,s0)";

          "@systemd@/share/factory(/.*)?" = "gen_context(system_u:object_r:systemd_factory_conf_t,s0)";
        };
      };
    };
  };
}
