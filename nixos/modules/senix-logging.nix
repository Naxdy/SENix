{ ... }: {
  # Journald (`syslogd_t`) access that the reference policy either does not
  # grant at all or that is expressed for a boot flow we do not have. Where a
  # reference policy statement only needs to be adapted to SENix, the
  # adaptation is noted inline; where another distribution already solved the
  # same problem, its solution is mirrored.
  config.security.selinux.modules.senix_logging = {
    layer = "system";
    typeEnforcement = ''
      policy_module(senix_logging)

      gen_require(`
        type kernel_t;
        type syslogd_t;
        type systemd_unit_t;
        type var_t;
        type var_log_t;
      ')

      # Systemd hands the listening sockets it opened for a unit (its socket
      # units and the `FileDescriptorStore`) on to the service it starts, and
      # those sockets are inherited across switch-root. They are created before
      # the policy is loaded, and a socket's label defaults to the type of the
      # task that created it (`security_compute_sid()` uses the source type for
      # socket classes), so they are labelled `kernel_t` rather than with the
      # type their file context assigns. The reference policy's
      # `kernel_*_dgram_sockets` interfaces already cover `unix_dgram_socket`
      # for `syslogd_t` apart from the socket-option operations journald
      # performs on the descriptors it was passed: `getopt` (classifying them,
      # `getsockopt()`) and `setopt` (enabling `SO_PASSCRED`, `setsockopt()`)
      # — Fedora allows the same set for the very same reason.
      allow syslogd_t kernel_t:unix_dgram_socket { getopt setopt };

      # The same handover happens for journald's *stream* socket (the
      # `/run/systemd/journal/stdout` it reads clients from): upstream grants
      # the full `rw_stream_socket_perms` for it — `init_rw_stream_sockets()`
      # in `logging.te`, "receive initramfs journald sockets" — which includes
      # the `listen`/`accept` pair, while the reference policy's
      # `kernel_rw_stream_sockets()` (what our `kernel_t`-labelled sockets get)
      # stops at `rw_socket_perms`. Without `accept` journald cannot pick up
      # the clients of the socket it inherited.
      allow syslogd_t kernel_t:unix_stream_socket { listen accept };

      # When journald starts before whatever creates `/var/log` (on NixOS the
      # tmpfiles rules for `/var` run later in the boot) it creates the
      # directory itself and then its journal directory inside it. Fedora
      # declares exactly the same transition so that the directory journald
      # creates is a log directory rather than generic `/var` content
      # (`files_var_filetrans(syslogd_t, var_log_t, dir, "log")` in their
      # `logging.te`), which of course also needs the permission to create it
      # in `/var`.
      allow syslogd_t var_t:dir { add_name write };
      files_var_filetrans(syslogd_t, var_log_t, dir, "log")

      # journald registers a PSI trigger on its own cgroup's `memory.pressure`
      # file, which it then `getattr`s, opens, and writes to. The reference
      # policy types that file `memory_pressure_t` — a dedicated type so that a
      # process can watch pressure without access to the rest of the cgroup
      # tree — and grants `syslogd_t` exactly those permissions
      # (`fs_watch_memory_pressure()`); the type comes from a file transition
      # declared for `init_t` (`fs_cgroup_filetrans_memory_pressure()` in
      # `init.te`), as PID1 enables the controllers and thereby makes the
      # kernel create the file.
      #
      # In SENix the initrd sets up the cgroup tree while PID1 is still
      # `kernel_t` (the policy is loaded by the `selinux-init` service, and
      # PID1 only becomes `init_t` when the host systemd re-executes itself
      # after the switch-root), so declare the same transition for the other
      # domain that creates cgroup files here. (The labels only take effect
      # once `selinux-cgroup-seed` has given the tree stored labels for the
      # kernel to derive them from.)
      fs_cgroup_filetrans_memory_pressure(kernel_t, file, "memory.pressure")

      # journald reads the per-unit log state PID1 exports to
      # `/run/systemd/units` (`invocation:<unit>` and `log-level-max:<unit>` as
      # symlinks, `log-extra-fields:<unit>` and `log-rate-limit-{interval,burst}:<unit>`
      # as small files) to tag the messages it receives. The reference policy
      # labels that tree `systemd_unit_t` but grants `syslogd_t` nothing on it
      # at all; Fedora grants the equivalent of
      # `systemd_read_unit_files(syslogd_t)` (their unit file types carry the
      # same label over there).
      allow syslogd_t systemd_unit_t:dir list_dir_perms;
      allow syslogd_t systemd_unit_t:file read_file_perms;
      allow syslogd_t systemd_unit_t:lnk_file read_lnk_file_perms;
    '';
  };
}
