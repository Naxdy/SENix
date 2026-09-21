{ ... }: {
  # This NixOS module supplies `.fc` configs with FHS paths corrected to work with
  # the Nix store, while the `.te`/`.if` are left to the Reference Policy source.

  imports = [
    ./bubblewrap.nix
    ./chromium.nix
    ./corecommands.nix
    ./dbus.nix
    ./files.nix
    ./init.nix
    ./libraries.nix
    ./logging.nix
    ./nscd.nix
    ./selinuxutil.nix
    ./senix-init.nix
    ./senix-logging.nix
    ./senix-store.nix
    ./systemd.nix
  ];
}
