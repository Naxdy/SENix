{ rustToolchain }:
{ ... }:
let
  cargoToml = builtins.fromTOML (builtins.readFile ./pkgs/metafs/Cargo.toml);
in
{
  programs = {
    nixfmt.enable = true;

    black.enable = true;

    rustfmt = {
      enable = true;
      package = rustToolchain;
      edition = cargoToml.package.edition;
    };

    typos = {
      enable = true;
      includes = [
        "*.md"
        "*.nix"
      ];
      # `nixos/modules/base` is generated verbatim from the Reference Policy
      # (see scripts/gen-base.py); spell-checking upstream policy text is noise.
      excludes = [
        "nixos/modules/base/**"
      ];
    };
  };
}
