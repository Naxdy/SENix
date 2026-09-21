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
        type syslogd_t;
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

      # Systemd hands the listening sockets it opened for a unit (its socket units
      # and the `FileDescriptorStore`) on to the service it starts, and those
      # sockets are inherited across switch-root. They are created before the
      # policy is loaded, and a socket's label defaults to the type of the task
      # that created it (`security_compute_sid()` uses the source type for socket
      # classes), so they are labelled `kernel_t` rather than with the type their
      # file context assigns. The reference policy's `kernel_*_dgram_sockets`
      # interfaces already cover `unix_dgram_socket` for `syslogd_t` apart from
      # the socket-option operations journald performs on the descriptors it was
      # passed: `getopt` (classifying them, `getsockopt()`) and `setopt`
      # (enabling `SO_PASSCRED`, `setsockopt()`) — Fedora allows the same set for
      # the very same reason.
      allow syslogd_t kernel_t:unix_dgram_socket { getopt setopt };
    '';
    fileContext = {
      rules = {
        "/var/empty" = "gen_context(system_u:object_r:var_t,s0)";
      };
    };
  };
}
