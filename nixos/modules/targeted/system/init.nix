{ config, lib, ... }:
let
  # Units are labeled `systemd_unit_t` by the catch-all below unless another
  # module claims them: our own `selinux*` services belong to `systemd.nix`, and
  # a module can opt a unit out via `security.selinux.exclusions.systemdUnits`
  # (e.g. `restorecond.nix`, which labels its unit `restorecond_unit_t`
  # instead). Two modules assigning different types to the same unit store path
  # is a conflicting file context rule, which `semodule` rejects outright.
  claims = name: !(lib.elem name config.security.selinux.exclusions.systemdUnits);
in
{
  security.selinux.modules.init = {
    fileContext = {
      storePaths = {
        systemd = [
          config.systemd.package
          config.boot.initrd.systemd.package
        ];
        # `config.systemd.packages` entries are not always real packages: nixpkgs'
        # `nix` is an `lndir` aggregate (`nix-everything`) that merges its
        # components' trees into `$out` by symlink, so the unit files it
        # contributes are symlinks into the `nix-cli` component, which is where
        # the real files live. metafs labels per path, and systemd opens — and
        # checks `{ status }` against (`tclass=service`) — that *resolved* file,
        # so the component needs the label, not the aggregate.
        packages = lib.unique (
          let
            unitsPackages = config.systemd.packages ++ config.boot.initrd.systemd.packages;
          in
          unitsPackages ++ lib.concatMap (p: lib.optionals (p ? nix-cli) [ p.nix-cli ]) unitsPackages
        );
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

  security.selinux.modules.senix_init = {
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
        type lib_t;
        type var_lib_t;
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
      # regular files, while the reference policy manages symlinks per type
      # (`files_manage_etc_symlinks()` and friends) — there is no equivalent for
      # the two directories whose symlinks NixOS's tmpfiles owns: the GC roots
      # in `/nix/var/nix/gcroots` (`var_lib_t`) and the binary-compat loader
      # link in `/lib64` (`lib_t`).
      allow systemd_tmpfiles_t var_lib_t:lnk_file { create getattr read };
      allow systemd_tmpfiles_t lib_t:lnk_file { create getattr };

      # `systemd`'s generators resolve executables off `PATH` and read locale
      # data (both out of the store, which `libraries.nix` labels properly:
      # `bin_t` for executables, `locale_t` for `share/locale`,
      # `share/X11/locale` and `share/i18n`).
      miscfiles_read_localization(systemd_generator_t);
      miscfiles_read_localization(systemd_journal_init_t);

      # Additionally both resolve the system profile, i.e. the
      # `/run/current-system/sw` symlink in the system closure — which is
      # `usr_t` (the store analogue of `/usr`), so reading the link itself is
      # the standard "usr symlink" access.
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
