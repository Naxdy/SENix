{ ... }: {
  imports = [
    ./accountsd.nix
    ./dbus.nix
    ./fail2ban.nix
    ./nscd.nix
    ./policykit.nix
    ./xserver.nix
  ];
}
