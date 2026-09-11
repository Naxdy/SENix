{ config, ... }: {
  # Grants for the domain that the initrd `selinux-init` and boot-time
  # `selinux-relabel` services run as (`init_unit_t`, declared in the
  # `init_context` base module). Those services run *before* the policy is
  # loaded, so systemd starts them with an explicit `SELinuxContext=`; they
  # must be able to run the SELinux userland tools directly (no `type_transition
  # ` exists from this new domain) and to `associate` a new label onto the
  # filesystems they walk — the kernel gates `setfattr` of `security.selinux`
  # on the `associate` permission on the `filesystem` class.
  #
  # These rules live in a system-layer module because they reference
  # system-layer types (`semanage_exec_t`, `selinux_config_t`, ...) that a base
  # module cannot see. `systemd_unit_t` gets the same treatment as a safety net:
  # if systemd falls back to it when the service is started before the policy is
  # loaded, the relabel still works.
  config.security.selinux.modules.selinux_tools = {
    layer = "system";
    typeEnforcement = ''
      policy_module(selinux_tools)
      gen_require(`
        type semanage_exec_t;
        type load_policy_exec_t;
        type setfiles_exec_t;
        type checkpolicy_exec_t;
        type selinux_config_t;
        type policy_config_t;
        type semanage_store_t;
        type systemd_unit_t;
        type init_t;
        type init_unit_t;
        type root_t;
        type device_t;
        type tmpfs_t;
        type fs_t;
        type bin_t;
        type shell_exec_t;
        type lib_t;
      ')

      allow init_unit_t { root_t device_t tmpfs_t fs_t }:filesystem associate;
      allow init_unit_t { semanage_exec_t load_policy_exec_t setfiles_exec_t checkpolicy_exec_t }:file execute_no_trans;
      allow init_unit_t { bin_t shell_exec_t }:file { read execute };
      allow init_unit_t lib_t:file read;
      allow init_unit_t lib_t:dir search;
      allow init_unit_t init_unit_t:process execmem;
      allow init_unit_t init_unit_t:capability2 checkpoint_restore;
      allow init_unit_t { selinux_config_t policy_config_t semanage_store_t }:file { read write };
      allow init_unit_t selinux_config_t:dir search;

      # systemd (PID 1, `init_t`) spawns the init/relabel services with an
      # explicit `SELinuxContext=`; the kernel requires a `process transition`
      # to change the exec context to `init_unit_t`.
      type_transition init_t init_unit_t:process init_unit_t;
      allow init_t init_unit_t:process transition;
      allow init_t init_unit_t:file { read execute getattr };
      allow init_t init_unit_t:dir search;
      allow systemd_unit_t { root_t device_t tmpfs_t fs_t }:filesystem associate;
      allow systemd_unit_t { semanage_exec_t load_policy_exec_t setfiles_exec_t checkpolicy_exec_t }:file execute_no_trans;
      allow systemd_unit_t { bin_t shell_exec_t }:file { read execute };
    '';
  };
}
