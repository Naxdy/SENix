{ config, ... }: {
  # The store is labelled at boot through a metacopy overlay whose upper
  # filesystem is a dedicated tmpfs ("the meta tmpfs") mounted at
  # `/run/selinux/overlay` (see `init-selinux-overlay`). Objects are copy-up'd
  # into that tmpfs as labels are applied. Without an explicit identity for that
  # filesystem, copy-up'd objects would resolve to an uncontrolled state
  # (`unlabeled_t` is not a `file_type`, so the copy-up create/`associate` gate
  # fails).
  #
  # Design:
  #   * `senix_meta_t` is BOTH the filesystem type and the default file label
  #     of the meta tmpfs: it is remounted with
  #     `context=system_u:object_r:senix_meta_t:s0` (see `selinux-relabel`), so
  #     every object on it - files, dirs, copy-up targets - automatically
  #     inherits `senix_meta_t` from the mount context. Nothing on it is ever
  #     `unlabeled_t`.
  #   * systemd's post-boot relabel then transitions those copy-up objects onto
  #     the real store labels (usr_t/bin_t/...), like any other store file.
  #
  # Type declared with Reference Policy interfaces (base module: the type must
  # always be present because the mount option references it directly). The
  # relabel grants use CONCRETE store types, never the `file_type` attribute:
  # refpolicy neverallows only authorize specific domains to relabel onto
  # sensitive types (`shadow_t`, `policy_config_t`, ...), and granting
  # `file_type:file relabelto` from our domains would violate them.
  config.security.selinux.modules.senix_store = {
    layer = "kernel";
    typeEnforcement = ''
      policy_module(senix_store)

      gen_require(`
        attribute file_type;
        type init_t;
        type init_unit_t;
        type setfiles_t;
        type usr_t;
        type bin_t;
        type lib_t;
        type ld_so_t;
        type shell_exec_t;
        type systemd_unit_t;
        type init_exec_t;
        type default_t;
        type ldconfig_exec_t;
        type etc_t;
        type var_t;
        type var_lib_t;
        type home_root_t;
        type tmp_t;
      ')

      type senix_meta_t;
      files_mountpoint(senix_meta_t);

      # The meta superblock is `senix_meta_t` (mounted with context=). Objects
      # created there inherit senix_meta_t from the mount context, so the
      # copy-up create's `associate` is self; and systemd relabels them onto
      # real store labels (usr_t/...), which must also associate onto this
      # superblock.
      allow senix_meta_t senix_meta_t:filesystem associate;
      allow file_type senix_meta_t:filesystem associate;

      # systemd (init_t) relabels the copy-up objects FROM `senix_meta_t` onto
      # the store labels; the initrd tools (init_unit_t/setfiles_t) need the
      # same path while they drive the initrd relabel. Concrete store + root
      # target types (neverallow-safe).
      allow { init_t init_unit_t setfiles_t } senix_meta_t:{ file dir lnk_file } { relabelfrom getattr };
      allow { init_t init_unit_t setfiles_t } { usr_t bin_t lib_t ld_so_t shell_exec_t systemd_unit_t init_exec_t default_t ldconfig_exec_t etc_t var_t var_lib_t home_root_t tmp_t }:{
        file dir lnk_file
      } relabelto;
    '';
  };
}
