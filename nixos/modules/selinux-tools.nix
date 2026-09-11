{ config, ... }: {
  # The initrd `selinux-init` and boot-time `selinux-relabel` services. The
  # boot-time service runs as a dedicated `init_unit_t` domain (requested up
  # front via `SELinuxContext=`), and the SELinux userland tools it spawns run
  # under their own Reference Policy domains (`semanage_t`, `load_policy_t`,
  # `setfiles_t`) which already hold the full relabel / store-management grants.
  #
  # The initrd `selinux-init` cannot get that domain: it is spawned before the
  # policy is loaded, so systemd cannot apply `SELinuxContext=` and falls back
  # to the unit file's context (`systemd_unit_t`). We therefore also grant
  # `systemd_unit_t` the `associate` permission — the one Reference Policy type
  # grant we cannot avoid, because that process is the only thing able to label
  # the store before the policy exists.
  #
  # These rules live in a system-layer module because they reference
  # system-layer types + interfaces (`seutil_domtrans_*`) that a base module
  # cannot see.
  config.security.selinux.modules.selinux_tools = {
    layer = "system";
    typeEnforcement = ''
      policy_module(selinux_tools)
      gen_require(`
        attribute domain;
        type init_t;
        type root_t;
        type device_t;
        type tmpfs_t;
        type fs_t;
        type selinux_config_t;
        type systemd_unit_t;
        type init_exec_t;
        type shell_exec_t;
        type setfiles_t;
        type unlabeled_t;
        type lib_t;
        type var_t;
        type var_lib_t;
        type tmp_t;
        type ld_so_t;
        type kernel_t;
        type etc_t;
        type nscd_runtime_t;
        type bin_t;
        type usr_t;
        type ldconfig_exec_t;
        type newrole_exec_t;
        type run_init_exec_t;
        type mount_runtime_t;
        type home_root_t;
        type proc_t;
        type enforce_learn_exec_t;
        role system_r;
      ')

      # The domain for the initrd `selinux-init` + boot-time `selinux-relabel`
      type init_unit_t;
      role object_r types init_unit_t;
      role system_r types init_unit_t;
      typeattribute init_unit_t domain;
      type_transition init_t init_unit_t:process init_unit_t;
      allow init_t init_unit_t:process transition;
      allow init_t init_unit_t:file { read execute getattr };

      # Promote to a full init-style domain (the interface grants the broad
      # file/dir/socket access a boot process needs to run bash + the tools).
      init_domain(init_unit_t, init_unit_t)

      # The SELinux userland tools run as their own domains, which already have
      # the full relabel / semanage grants; `init_unit_t` only allows the
      # transition (and the required store/bin search).
      seutil_domtrans_semanage(init_unit_t)
      seutil_domtrans_loadpolicy(init_unit_t)
      seutil_domtrans_setfiles(init_unit_t)
      seutil_domtrans_checkpolicy(init_unit_t)

      # The service shell, `find`, `setfattr`, shell utilities etc. run as
      # `init_unit_t`; it must `associate` a label onto the filesystems it
      # walks (the kernel gates setting `security.selinux` on that permission)
      # and exec the shell + coreutils.
      # The service shell, `find`, `setfattr` etc. run as `init_unit_t`; it must
      # `associate` a label onto the filesystems it walks and exec the shell +
      # coreutils. The actual relabeling is done by the SELinux tool binaries
      # (`restorecon`/`setfiles`), which are labeled `setfiles_exec_t` in the
      # initrd and transition to `setfiles_t` — we grant that domain the relabel
      allow init_unit_t { bin_t shell_exec_t init_exec_t }:file { read getattr open map execute execute_no_trans relabelto relabelfrom entrypoint };
      allow init_unit_t systemd_unit_t:file { read getattr open execute relabelto relabelfrom entrypoint };
      allow init_unit_t { usr_t lib_t ld_so_t ldconfig_exec_t }:file { read getattr open map execute execute_no_trans relabelto relabelfrom };
      allow init_unit_t { usr_t bin_t lib_t ld_so_t }:dir { read search getattr open relabelto relabelfrom };
      allow init_unit_t { usr_t bin_t lib_t ld_so_t }:lnk_file { read getattr relabelto relabelfrom };
      allow init_unit_t { systemd_unit_t }:dir { read search getattr open relabelto relabelfrom };
      allow init_unit_t { systemd_unit_t }:lnk_file { read getattr relabelto relabelfrom };
      allow init_unit_t { semanage_exec_t load_policy_exec_t setfiles_exec_t checkpolicy_exec_t newrole_exec_t run_init_exec_t enforce_learn_exec_t }:file { read getattr open map execute execute_no_trans relabelto relabelfrom entrypoint };
      allow init_unit_t { unlabeled_t root_t }:file { read getattr open map execute execute_no_trans relabelto relabelfrom };
      allow init_unit_t unlabeled_t:dir { read search open getattr };
      allow init_unit_t { unlabeled_t root_t tmpfs_t }:dir { read search getattr open relabelto relabelfrom };
      allow init_unit_t { tmpfs_t root_t fs_t device_t }:dir search;
      allow init_unit_t { init_t kernel_t }:fd use;
      allow init_unit_t tmpfs_t:dir { write add_name remove_name create };
      allow init_unit_t { tmpfs_t tmp_t var_t root_t }:dir { write add_name remove_name };
      allow init_unit_t selinux_config_t:dir { create add_name search getattr open };
      allow init_unit_t unlabeled_t:file ioctl;
      allow init_unit_t systemd_unit_t:file ioctl;
      allow init_unit_t init_t:unix_stream_socket { connectto rw_socket_perms };
      allow init_unit_t init_t:fifo_file rw_fifo_file_perms;
      allow init_unit_t etc_t:file { read getattr open };
      allow init_unit_t etc_t:lnk_file read;
      allow init_unit_t unlabeled_t:lnk_file read;
      allow init_unit_t tmpfs_t:lnk_file read;
      allow init_unit_t tmpfs_t:filesystem mount;
      allow init_unit_t tmpfs_t:dir mounton;
      allow init_unit_t proc_t:file { read getattr open };
      allow init_unit_t selinux_config_t:lnk_file read;
      allow init_unit_t selinux_config_t:file read;
      allow init_unit_t nscd_runtime_t:dir search;
      allow init_unit_t nscd_runtime_t:sock_file rw_sock_file_perms;
      allow init_unit_t { mount_runtime_t home_root_t }:dir { read search getattr open };
      allow init_unit_t mount_runtime_t:file { read write getattr open };
      allow init_unit_t self:capability { chown dac_override dac_read_search fowner fsetid setuid setgid mknod net_bind_service sys_admin sys_resource sys_chroot };

      # `setfiles_t` relabels the store + the non-store root. The Reference
      # Policy only grants it the SELinux-specific reads + relabelfrom-unlabeled,
      # so it cannot relabel the generic store/root types; grant it the access.
      allow setfiles_t { usr_t bin_t lib_t ld_so_t ldconfig_exec_t shell_exec_t init_exec_t }:file { read getattr open relabelto relabelfrom };
      allow setfiles_t { usr_t bin_t lib_t ld_so_t }:dir { read search getattr open relabelto relabelfrom };
      allow setfiles_t { systemd_unit_t }:file { read getattr open relabelto relabelfrom };
      allow setfiles_t { systemd_unit_t }:dir { read getattr open search relabelto relabelfrom };
      allow setfiles_t { etc_t var_t var_lib_t }:file { read getattr open relabelto relabelfrom };
      allow setfiles_t { etc_t var_t var_lib_t }:dir { read getattr open search relabelto relabelfrom };
      allow setfiles_t { semanage_exec_t load_policy_exec_t setfiles_exec_t checkpolicy_exec_t newrole_exec_t run_init_exec_t enforce_learn_exec_t }:file relabelto;
      allow setfiles_t { unlabeled_t root_t }:file { getattr relabelto relabelfrom };
      allow setfiles_t { unlabeled_t root_t }:dir { getattr relabelto relabelfrom };
      allow setfiles_t { tmpfs_t }:dir { getattr relabelto relabelfrom };
      allow setfiles_t tmpfs_t:filesystem associate;
    '';
    # `/var/empty` has no rule in the Reference Policy (only its subpaths like
    # `/var/empty/dev`); without one `setfiles` cannot determine a context for
    # it during the relabel, so give it the `/var` type explicitly.
    fileContext = {
      rules = {
        "/var/empty" = "gen_context(system_u:object_r:var_t,s0)";
      };
    };
  };
}
