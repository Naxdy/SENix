{ rustToolchain }:
{ ... }:
let
  cargoToml = builtins.fromTOML (builtins.readFile ./Cargo.toml);
in
{
  programs = {
    nixfmt.enable = true;

    rustfmt = {
      enable = true;
      package = rustToolchain;
      edition = cargoToml.workspace.package.edition;
    };

    taplo.enable = true;

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
