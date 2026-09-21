{ ... }: {
  # This NixOS module supplies `.fc` configs with FHS paths corrected to work with
  # the Nix store, while the `.te`/`.if` are left to the Reference Policy source.

  imports = [
    ./base
    ./bubblewrap.nix
    ./chromium.nix
    ./dbus.nix
    ./files.nix
    ./init.nix
    ./logging.nix
    ./nscd.nix
    ./selinuxutil.nix
    ./senix-init.nix
    ./senix-logging.nix
    ./senix-store.nix
    ./systemd.nix
  ];
}
