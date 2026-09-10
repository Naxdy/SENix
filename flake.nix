{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      treefmt-nix,
    }:
    let
      inherit (nixpkgs) lib;

      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      forEachSupportedSystem =
        f:
        lib.genAttrs supportedSystems (
          system:
          let
            pkgs = import nixpkgs {
              inherit system;
              config.allowUnfree = true;
            };

            treefmtEval = treefmt-nix.lib.evalModule pkgs ./treefmt.nix;

            treefmt = treefmtEval.config.build.wrapper;
          in
          f {
            inherit
              system
              pkgs
              treefmt
              treefmtEval
              ;
          }
        );
    in
    {
      devShells = forEachSupportedSystem (
        { pkgs, treefmt, ... }:
        {
          default = pkgs.mkShell {
            packages = [
              treefmt
            ];
          };
        }
      );

      formatter = forEachSupportedSystem ({ treefmt, ... }: treefmt);

      checks = forEachSupportedSystem (
        {
          system,
          pkgs,
          treefmtEval,
          ...
        }:
        {
          treefmt = treefmtEval.config.build.check self;

          selinux = import ./tests/screen/test.nix {
            inherit pkgs;
          };

          selinux-enforce = import ./tests/selinux-enforce/test.nix {
            inherit pkgs;
          };
        }
      );
    };
}
