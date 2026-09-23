{ ... }: {
  # "Targeted" modules exist to focus the relabeling within
  # `/nix/store` to only target programs & services that are
  # referenced by the current configuration, as opposed
  # to relying on catch-all patterns.

  imports = [
    ./apps
    ./kernel
    ./services
    ./system
  ];
}
