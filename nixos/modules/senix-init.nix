{ ... }: {
  config.security.selinux.modules.senix_init = {
    layer = "system";
    typeEnforcement = ''
      policy_module(senix_init)

      gen_require(`
        attribute non_security_file_type;
        class service { start status };
        class process2 { execmem nosuid_transition };
        class capability2 { checkpoint_restore };
        type kernel_t;
        type init_t;
        type initrc_t;
        type restorecond_t;
        type system_dbusd_t;
        type systemd_generator_t;
        type systemd_journal_init_t;
        type systemd_logind_t;
        type systemd_machine_id_setup_t;
        type systemd_sessions_t;
        type systemd_tmpfiles_t;
        type systemd_update_done_t;
        type init_runtime_t;
        type nscd_t;
      ')

      # Allows systemd to transition to init_t
      allow kernel_t init_t:process2 nosuid_transition;
      allow init_t self:process dyntransition;
      allow kernel_t self:process setcurrent;

      allow initrc_t self:capability2 checkpoint_restore;

      # grep in activation scripts
      allow initrc_t self:process execmem;

      # libsystemd.so currently is a kernel-owned fd when these services start
      # TODO: Figure out if there's a way to not need this.
      kernel_use_fds(system_dbusd_t);

      # `systemd-machine-id-setup` checks whether the namespace it is looking at
      # is really on nsfs (`fd_is_fs_type(fd, NSFS_MAGIC)` → `fstatfs()`), which
      # is the filesystem-level `getattr` — the reference policy grants that
      # only to the container engines (`fs_getattr_nsfs()` in
      # `container.te`), while machine-id-setup only gets the file-level
      # permissions (`fs_read_nsfs_files()` in `systemd.te`).
      fs_getattr_nsfs(systemd_machine_id_setup_t)

      # The same service queries its own capability set (`capget()`), which no
      # rule covers.
      allow systemd_machine_id_setup_t self:process getcap;

      # `systemd-tmpfiles` marks `/var/empty` immutable (NixOS ships a tmpfiles
      # rule with the `i` attribute); `CAP_LINUX_IMMUTABLE` is granted to the
      # package managers and the like, but not to the tmpfiles domain, because
      # no distribution asks it to set that flag.
      allow systemd_tmpfiles_t self:capability linux_immutable;

      # `systemd_tmpfiles_manage_all` (see `systemd.nix`) covers directories and
      # regular files, but NixOS also has tmpfiles rules that create *symlinks*
      # (`L` items) in paths it owns — `/lib64/ld-linux-x86-64.so.2`,
      # `/nix/var/nix/gcroots/{current,booted}-system` — and the reference
      # policy only grants symlink management per type
      # (`files_manage_etc_symlinks()` and friends). Extend the tunable's
      # attribute-wide grant to symlinks as well.
      allow systemd_tmpfiles_t non_security_file_type:lnk_file { create read getattr };

      # `restorecond` does NSS lookups (`auth_use_nsswitch()` in
      # `selinuxutil.te`). The socket it has to talk to is
      # `/run/nscd/socket`, which on NixOS belongs to `nsncd` — a binary the
      # policy has no transition for, so it runs in `initrc_t` and its socket
      # carries that domain (a socket's label defaults to the creating task's
      # type) instead of `nscd_runtime_t`.
      allow restorecond_t initrc_t:unix_stream_socket connectto;

      # `systemd`'s generators resolve executables from the store (e.g.
      # `fsck.ext4` for the fstab generator), and the initrd journal's
      # `journalctl` reads locale data from it; SENix labels store paths with
      # the generic `usr_t` unless a more specific file context matches.
      files_read_usr_symlinks(systemd_generator_t);
      files_read_usr_files(systemd_journal_init_t);
      files_read_usr_symlinks(systemd_journal_init_t);

      # `systemd-user-sessions` and `systemd-update-done` follow symlinks in
      # `/etc` (the `mtab`/`localtime`/… compatibility links), and `restorecond`
      # watches the `/etc` files its configuration lists.
      files_read_etc_symlinks(systemd_sessions_t);
      files_read_etc_symlinks(systemd_update_done_t);
      files_watch_etc_files(restorecond_t);

      # `systemd-logind` creates its runtime sockets under `/run/systemd`
      # (`init_runtime_t` for everything without a more specific file context).
      allow systemd_logind_t init_runtime_t:sock_file create;
    '';
    fileContext = {
      rules = {
        "/var/empty" = "gen_context(system_u:object_r:var_t,s0)";
      };
    };
  };
}
