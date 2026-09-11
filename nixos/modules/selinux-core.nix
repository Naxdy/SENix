{ ... }: {
  # The systemd unit files are `unlabeled_t` during the boot window — the store is
  # only labeled once the relabel runs, but systemd must already be able to
  # start/stop/query units (e.g. to start the relabel itself). This grants a
  # service-class lifecycle right only; all file/dir access goes through the
  # labeled store types (usr_t/lib_t/bin_t from `libraries.nix`).
  config.security.selinux.modules.selinux_core = {
    typeEnforcement = ''
      policy_module(selinux_core)
      require {
        type init_t, initrc_t, unlabeled_t;
        class service { start status stop };
      }
      allow init_t unlabeled_t:service { start status stop };
      allow initrc_t unlabeled_t:service { start status stop };
    '';
  };
}
