{ ... }: {
  config.security.selinux.modules.senix_init = {
    layer = "system";
    typeEnforcement = ''
      policy_module(senix_init)

      gen_require(`
        class service { start status };
        class process2 { execmem nosuid_transition };
        class capability2 { checkpoint_restore };
        type kernel_t;
        type init_t;
        type initrc_t;
        type system_dbusd_t;
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
    '';
    fileContext = {
      rules = {
        "/var/empty" = "gen_context(system_u:object_r:var_t,s0)";
      };
    };
  };
}
