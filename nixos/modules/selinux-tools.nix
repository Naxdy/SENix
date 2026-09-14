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
        type initrc_t;
        type event_device_t;
        class service { start status };
        type bin_t;
        type usr_t;
        type ldconfig_exec_t;
        type newrole_exec_t;
        type run_init_exec_t;
        type mount_runtime_t;
        type home_root_t;
        type proc_t;
        type file_context_t;
        type policy_config_t;
        type default_context_t;
        type default_t;
      ')

      # The domain for the initrd `selinux-init` + boot-time `selinux-relabel`
      type init_unit_t;
      typeattribute init_unit_t domain;
      type_transition init_t init_unit_t:process init_unit_t;
      allow init_t init_unit_t:process transition;
      allow init_t init_unit_t:file { read execute getattr };

      # PID 1 resolves to `kernel_t` (the `kernel` SID); the `init` SID is the
      # Reference Policy's own `unlabeled_t`. systemd re-execs the `init_exec_t`
      # binary to become `init_t`, so we allow the transition from both possible
      # starting contexts.
      allow { kernel_t unlabeled_t } init_exec_t:file execute;
      type_transition { kernel_t unlabeled_t } init_exec_t:process init_t;
      allow { kernel_t unlabeled_t } init_t:process transition;
      allow { kernel_t unlabeled_t } init_t:process2 nosuid_transition;
      allow init_t init_t:process execmem;
      allow init_t init_t:capability2 checkpoint_restore;
      allow init_exec_t root_t:filesystem associate;
      allow init_exec_t tmpfs_t:filesystem associate;

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
      allow init_unit_t { semanage_exec_t load_policy_exec_t setfiles_exec_t checkpolicy_exec_t newrole_exec_t run_init_exec_t }:file { read getattr open map execute execute_no_trans relabelto relabelfrom entrypoint };
      allow init_unit_t { unlabeled_t root_t default_t }:file { read getattr open map execute execute_no_trans relabelto relabelfrom };
      allow init_unit_t unlabeled_t:dir { read search open getattr };
      allow init_unit_t default_t:dir { read search getattr open relabelto relabelfrom };
      allow init_unit_t default_t:lnk_file read;
      allow init_unit_t { unlabeled_t root_t tmpfs_t }:dir { read search getattr open relabelto relabelfrom };
      allow init_unit_t { tmpfs_t root_t fs_t device_t }:dir search;
      allow init_unit_t { init_t kernel_t unlabeled_t }:fd use;

      # We operate single-level (s0) on top of an MLS policy; refpolicy assigns
      # the `kernel`/`unlabeled` SIDs `mls_systemhigh` (:s15:c0.c1023), so
      # unlabelled store objects carry the high level. The compiled policy's
      # `validatetrans` constraints on file/dir require the new label to carry
      # the same level as the old (or key off the mlsfileupgrade /
      # mlsfiledowngrade exemptions). Grant the boot/relabel domains BOTH of
      # those designated exemptions (upgrade + downgrade) so systemd/the initrd
      # can label the store regardless of the range on the current label. Also
      # give them all-levels file read/write so they can work with the objects
      # while they still carry the high level. (Macros from mls.if.)
      mls_file_upgrade(init_t)
      mls_file_upgrade(init_unit_t)
      mls_file_upgrade(setfiles_t)
      mls_file_upgrade(kernel_t)
      mls_file_upgrade(initrc_t)
      mls_file_downgrade(init_t)
      mls_file_downgrade(init_unit_t)
      mls_file_downgrade(setfiles_t)
      mls_file_downgrade(kernel_t)
      mls_file_downgrade(initrc_t)
      mls_file_read_all_levels(init_t)
      mls_file_read_all_levels(init_unit_t)
      mls_file_read_all_levels(setfiles_t)
      mls_file_write_all_levels(init_t)
      mls_file_write_all_levels(init_unit_t)
      mls_file_write_all_levels(setfiles_t)
      # PID 1 is `init_t` (the `kernel_t -> init_t` exec transition works and is
      # verified), but the boot-time fd/socket objects systemd hands to its
      # child units are still labeled with the `kernel` initial SID
      # (`kernel_t`, pinned by kernel.te to mls_systemhigh): every task is born
      # with SECINITSID_KERNEL and objects created in that early window (exec
      # fds, kernel-netlink peers) keep it forever. Using such an fd is
      # `fd:use` against `kernel_t:s15:c0.c1023`, which refpolicy never grants
      # (it only covers init_t/initrc_t-owned fds) and which the MLS constraint
      # `mlsconstrain fd use (l1 eq l2 or t1==mlsfduse or t2==mlsfdshare)`
      # refuses at unequal levels. Legitimize it with refpolicy's own escape
      # hatch: `mls_fd_share_all_levels` marks *the owner type's* fds as
      # shareable across levels, the unit domains get the explicit `use`.
      # Mirrors the grants Fedora ships in policy/modules/kernel/kernel.te
      # (`mls_fd_share_all_levels(kernel_t)` + `mls_fd_use_all_levels(kernel_t)`
      # under ifdef(`enable_mls'); the reverse direction is currently inert for
      # us since no kernel_t task consumes foreign fds, but is kept for parity).
      mls_fd_share_all_levels(kernel_t)
      mls_fd_use_all_levels(kernel_t)
      allow { initrc_t init_unit_t } kernel_t:fd use;
      # PID 1 is `kernel_t` (the `kernel` SID) → `unlabeled_t` (the `init` SID);
      # it spawns the relabel via `SELinuxContext=`, so allow that transition +
      # the fd/socket inheritance from it.
      allow { kernel_t unlabeled_t } init_unit_t:process transition;
      allow { kernel_t unlabeled_t } init_unit_t:file execute;
      allow init_unit_t tmpfs_t:dir { write add_name remove_name create };
      allow init_unit_t { tmpfs_t tmp_t var_t root_t }:dir { write add_name remove_name };
      allow init_unit_t selinux_config_t:dir { create add_name search getattr open };
      allow init_unit_t unlabeled_t:file ioctl;
      allow init_unit_t systemd_unit_t:file ioctl;
      allow init_unit_t { init_t kernel_t unlabeled_t }:unix_stream_socket { connectto rw_socket_perms };
      allow init_unit_t { init_t kernel_t unlabeled_t }:fifo_file rw_fifo_file_perms;
      allow init_unit_t etc_t:file { read getattr open };
      allow init_unit_t etc_t:lnk_file read;
      allow init_unit_t unlabeled_t:lnk_file read;
      allow init_unit_t tmpfs_t:lnk_file read;
      allow init_unit_t tmpfs_t:filesystem mount;
      allow init_unit_t tmpfs_t:dir mounton;
      allow init_unit_t proc_t:file { read getattr open };
      allow init_unit_t selinux_config_t:lnk_file read;
      allow init_unit_t selinux_config_t:file read;
      # `restorecon`/`setfiles` must read the file_contexts + policy from
      # `/etc/selinux/<type>` (labeled `file_context_t`/`policy_config_t`).
      allow init_unit_t { file_context_t policy_config_t default_context_t }:dir { search read getattr open };
      allow init_unit_t { file_context_t policy_config_t default_context_t }:file { read getattr open map };
      allow init_unit_t { file_context_t policy_config_t default_context_t }:lnk_file read;
      allow init_unit_t { root_t device_t tmpfs_t fs_t }:filesystem { associate getattr };
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
      allow setfiles_t { semanage_exec_t load_policy_exec_t setfiles_exec_t checkpolicy_exec_t newrole_exec_t run_init_exec_t }:file relabelto;
      allow setfiles_t { unlabeled_t root_t }:file { getattr relabelto relabelfrom };
      allow setfiles_t { unlabeled_t root_t }:dir { getattr relabelto relabelfrom };
      allow setfiles_t { tmpfs_t }:dir { getattr relabelto relabelfrom };
      allow setfiles_t tmpfs_t:filesystem associate;

      # The initrd `selinux-init` cannot get `init_unit_t`: systemd spawns it
      # before the policy is loaded, so `SELinuxContext=` is not applied and the
      # process resolves to the unit-file type `systemd_unit_t` after
      # `load_policy` (the boot log shows its `setfattr` running as
      # `systemd_unit_t`, not `init_unit_t`). It must therefore be able to
      # `associate` labels onto the filesystems it walks — the one Reference
      # Policy type we extend.
      allow systemd_unit_t { root_t device_t tmpfs_t fs_t }:filesystem associate;

      # `init_unit_t` (the relabel) uses pipes / tmpfiles for logging + the
      # shell; the Reference Policy grants it neither.
      allow init_unit_t init_unit_t:fifo_file rw_fifo_file_perms;

      #
      # Running the relabel + seeding while enforcing (the selinux-enforce VM)
      # needs these additional grants; observed from the permissive boot AVCs.
      #
      # The relabel walks /dev nodes, ioctls its own binaries, connects to the
      # nscd socket, reads the /run/selinux fc tree, and transitions its
      # spawned tools under nnp/nosuid.
      allow init_unit_t event_device_t:chr_file { read write open getattr ioctl };
      allow init_unit_t { root_t bin_t }:file ioctl;
      allow init_unit_t initrc_t:unix_stream_socket connectto;
      allow init_unit_t setfiles_t:process2 nosuid_transition;
      allow init_unit_t tmpfs_t:file { read open getattr map };
      # setfiles crawls unreachable/unlabelled tree objects + the /run/selinux
      # store while relabeling the root + /dev.
      allow setfiles_t tmpfs_t:file { read open getattr map };
      allow setfiles_t event_device_t:chr_file { read getattr open };
      # The seed/rc processes (agetty etc.) run as initrc_t.
      allow initrc_t self:capability2 checkpoint_restore;
      allow initrc_t self:process execmem;
      # systemd (init_t / the rc domains) starting units whose unit files still
      # carry plain store (usr_t) labels needs the service class.
      allow { init_t initrc_t } usr_t:service { start status };
      # The boot-time setfiles/`setenforce 1` operate on the selinuxfs security
      # interface; without them enforcing never engages. Use the refpolicy
      # interfaces so the selinux neverallows (can_setenforce / check_context)
      # still hold.
      selinux_set_enforce_mode(init_unit_t)
      selinux_validate_context(init_unit_t)
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
