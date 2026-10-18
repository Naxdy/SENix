{
  config,
  lib,
  ...
}:
{
  # AccountsService is pulled into every display-manager flow that uses it
  # (Plasma 6, GNOME, SDDM, ...). The generated base module carries the
  # Reference Policy's rules verbatim; they predate the two reads this build
  # performs at startup. Add them only while the daemon is in the
  # configuration.
  config = lib.mkIf config.services.accounts-daemon.enable {
    security.selinux.modules.accountsd.typeEnforcement = lib.mkAfter ''
      # read /etc/machine-id
      files_read_etc_runtime_files(accountsd_t)

      # read selinux config
      seutil_read_config(accountsd_t)
    '';
  };
}
