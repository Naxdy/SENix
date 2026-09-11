{ config, ... }: {
  # The initrd `selinux-init` and boot-time `selinux-relabel` services run as
  # `systemd_unit_t` — systemd assigns the unit file's context because the
  # policy is not (yet) fully loaded — and the relabel tooling they spawn
  # (`restorecon`, `setfiles`) runs as `setfiles_t`. The Reference Policy's
  # `setfiles_t` only reads the SELinux-specific types and relabels *from*
  # `unlabeled_t`; it cannot read (hence label) the generic store/root types we
  # assign. These rules live in a system-layer module because they reference
  # system-layer types a base module cannot see.
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
        type setfiles_t;
        type root_t;
        type device_t;
        type tmpfs_t;
        type fs_t;
        type usr_t;
        type bin_t;
        type shell_exec_t;
        type lib_t;
        type ld_so_t;
        type ldconfig_exec_t;
        type etc_t;
        type var_t;
        type var_lib_t;
      ')

      # The initrd `selinux-init` runs `semodule`/`load_policy`/`setfattr` as
      # `systemd_unit_t`; it must associate labels onto the filesystems it
      # walks and exec the tool binaries directly (there is no `type_transition
      # ` from this domain).
      allow systemd_unit_t { root_t device_t tmpfs_t fs_t }:filesystem associate;
      allow systemd_unit_t { semanage_exec_t load_policy_exec_t setfiles_exec_t checkpolicy_exec_t }:file execute_no_trans;
      allow systemd_unit_t { bin_t shell_exec_t }:file { read execute };
      allow systemd_unit_t lib_t:file read;

      # `setfiles`/`restorecon` relabel the non-store root (`/etc`, `/var`);
      # the Reference Policy grants them only the SELinux-specific reads +
      # relabelfrom-unlabeled, so they cannot read/relabel the generic root
      # types. (The store's `usr_t`/`bin_t`/`lib_t` files are handled by the
      # matching file-context rules, which label the specific paths with the
      # right `selinux_config_t`/`etc_t`/... types instead.)
      allow setfiles_t { etc_t var_t var_lib_t }:file { read getattr open relabelto };
      allow setfiles_t { etc_t var_t var_lib_t }:dir { read open getattr search relabelto };
      allow setfiles_t { etc_t var_t var_lib_t }:lnk_file relabelto;
      allow setfiles_t { fs_t root_t tmpfs_t device_t }:filesystem associate;
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
