{ rustToolchain }:
{ ... }:
let
  cargoToml = builtins.fromTOML (builtins.readFile ./metafs/Cargo.toml);
in
{
  programs = {
    nixfmt.enable = true;

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
    };
  };
}
