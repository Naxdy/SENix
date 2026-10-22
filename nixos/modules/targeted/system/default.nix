{ ... }: {
  imports = [
    ./authlogin.nix
    ./init.nix
    ./logging.nix
    ./selinuxutil.nix
    ./systemd.nix
  ];
}
