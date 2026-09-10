{ ... }:
{
  # it can manage units, which the `service` class requires. The initrd labels
  # the systemd binary `init_exec_t` before it is exec'd (once the SELinux
  # policy is loaded), and these `type_transition`s carry that into `init_t`.
  config.security.selinux.modules.init_context = {
    # A base module (layer `kernel`) so the `sid init` statement — which
    # `checkmodule` only accepts in base modules — can make PID 1 (systemd)
    # run as `init_t`, giving it the `service` permissions it needs to boot in
    # enforcing mode. The kernel assigns PID 1 the `init` SID at boot, and when
    # the policy is loaded it resolves to the context set here.
    layer = "kernel";
    typeEnforcement = ''
      policy_module(init_context)
      # `init_t` / `init_exec_t` / `initrc_transition_domain` are moved here
      # from the `init` module (which we strip in `build.nix`), because a base
      # module cannot `require` a non-base type and `sid` is base-only.
      attribute initrc_transition_domain;
      type init_t, initrc_transition_domain;
      type init_exec_t;
      typeattribute init_t domain;
      role system_r types init_t;
      role object_r types init_exec_t;
      allow kernel_t init_exec_t:file execute;
      allow init_exec_t root_t:filesystem associate;
      allow init_exec_t tmpfs_t:filesystem associate;
      allow unlabeled_t tmpfs_t:filesystem associate;
      allow init_t unlabeled_t:service *;
      type_transition kernel_t init_exec_t:process init_t;
    '';
  };
}
