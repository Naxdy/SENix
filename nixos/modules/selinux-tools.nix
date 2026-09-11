{ config, ... }: {
  # The initrd `selinux-init` and boot-time `selinux-relabel` services run as a
  # dedicated `init_unit_t` domain, requested up front with `SELinuxContext=`
  # (systemd assigns the unit file's context otherwise — which is `systemd_unit_t`,
  # a Reference Policy file type that cannot `associate`). Rather than grant any
  # Reference Policy type new permissions, we give this custom domain the
  # accesses it needs and let the SELinux userland tools it spawns run under
  # their *own* Reference Policy domains (`semanage_t`, `load_policy_t`,
  # `setfiles_t`), which already hold the full relabel / store-management
  # grants.
  #
  # These rules live in a system-layer module because they reference
  # system-layer types + interfaces (`init_domain`, `seutil_domtrans_*`) that a
  # base module cannot see.
  config.security.selinux.modules.selinux_tools = {
    layer = "system";
    typeEnforcement = ''
      policy_module(selinux_tools)
      gen_require(`
        type init_t;
        type root_t;
        type device_t;
        type tmpfs_t;
        type fs_t;
        type bin_t;
        type shell_exec_t;
        type lib_t;
        type selinux_config_t;
      ')

      # The domain for the initrd `selinux-init` + boot-time `selinux-relabel`
      # services; `init_domain` (below) promotes it to a full init-style domain.
      type init_unit_t;
      role object_r types init_unit_t;
      # `init_unit_t` is a full init-style domain (the `init_domain` interface
      # gives it the `system_r` role, the `init_domain_type` attribute, and the
      # `init_t -> init_unit_t` process transition systemd needs to spawn it
      # through `SELinuxContext=`).
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
      allow init_unit_t { root_t device_t tmpfs_t fs_t }:filesystem associate;
      allow init_unit_t { bin_t shell_exec_t }:file { read getattr open execute };
      allow init_unit_t lib_t:file read;
      allow init_unit_t lib_t:dir search;
      allow init_unit_t init_unit_t:process execmem;
      allow init_unit_t selinux_config_t:dir search;
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
