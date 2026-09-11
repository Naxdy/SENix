{ config, ... }: {
  # A base module (layer `kernel`) so the `sid init` statement — which
  # `checkmodule` only accepts in base modules — can make PID 1 (systemd) run
  # as `init_t`, giving it the `service` permissions it needs to boot in
  # enforcing mode. The kernel assigns PID 1 the `init` SID at boot, and when
  # the policy is loaded it resolves to the context set here.
  #
  # This module only *declares* `init_unit_t` (the domain the initrd/relabel
  # service runs as via `SELinuxContext=`); the rules that reference
  # system-layer types (the SELinux userland tools, the semanage store, etc.)
  # live in the `selinux_tools` module, because a base module cannot see
  # system-layer types.
  config.security.selinux.modules.init_context = {
    layer = "kernel";
    typeEnforcement = ''
      policy_module(init_context)
      # `init_t` / `init_exec_t` / `initrc_transition_domain` are moved here
      # from the `init` module (which we strip in `build.nix`), because a base
      # module cannot `require` a non-base type and `sid` is base-only.
      attribute initrc_transition_domain;
      type init_t, initrc_transition_domain;
      type init_exec_t;
      type init_unit_t;

      typeattribute init_t domain;
      typeattribute init_unit_t domain;
      role system_r types init_t;
      role system_r types init_unit_t;
      role object_r types init_exec_t;
      role object_r types init_unit_t;

      allow kernel_t init_exec_t:file execute;
      allow init_exec_t root_t:filesystem associate;
      allow init_exec_t tmpfs_t:filesystem associate;
      allow unlabeled_t tmpfs_t:filesystem associate;

      # The activation scripts run store tools (grep, semodule, ...) under
      # `init_t`; those tools mmap executable anonymous memory (e.g. regex) and
      # agetty requests CAP_CHECKPOINT_RESTORE, neither of which the Reference
      # Policy's `init` module grants to `init_t`.
      allow init_t init_t:process execmem;
      allow init_t init_t:capability2 checkpoint_restore;
      type_transition kernel_t init_exec_t:process init_t;
    '';
  };
}
