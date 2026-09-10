{ ... }: {
  # This NixOS module supplies `.fc` configs with FHS paths corrected to work with
  # the Nix store, while the `.te`/`.if` are left to the Reference Policy source.

  imports = [
    ./chromium.nix
    ./init-context.nix
    ./init.nix
    ./systemd.nix
  ];
}
