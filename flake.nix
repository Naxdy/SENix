{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    crane.url = "github:ipetkov/crane";
  };

  outputs =
    {
      self,
      nixpkgs,
      treefmt-nix,
      fenix,
      crane,
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
              overlays = [
                fenix.overlays.default
                self.overlays.default
              ];
            };

            treefmtEval = treefmt-nix.lib.evalModule pkgs (
              import ./treefmt.nix {
                inherit rustToolchain;
              }
            );

            treefmt = treefmtEval.config.build.wrapper;

            rustToolchain = pkgs.fenix.stable.withComponents [
              "cargo"
              "clippy"
              "rust-analyzer"
              "rust-src"
              "rust-std"
              "rustc"
              "rustfmt"
            ];
          in
          f {
            inherit
              pkgs
              rustToolchain
              system
              treefmt
              treefmtEval
              ;
          }
        );
    in
    {
      devShells = forEachSupportedSystem (
        {
          pkgs,
          rustToolchain,
          treefmt,
          ...
        }:
        {
          default = pkgs.mkShell {
            packages = [
              rustToolchain
              treefmt
            ];
          };
        }
      );

      packages = forEachSupportedSystem (
        { pkgs, ... }: {
          metafs = pkgs.pkgsStatic.callPackage ./metafs { inherit crane; };
        }
      );

      overlays.default = final: prev: {
        inherit (self.packages.${final.stdenv.hostPlatform.system}) metafs;
      };

      formatter = forEachSupportedSystem ({ treefmt, ... }: treefmt);

      checks = forEachSupportedSystem (
        {
          system,
          pkgs,
          treefmtEval,
          ...
        }:
        let
          testsFrom =
            pname:
            lib.mapAttrs' (name: value: {
              name = "${pname}-${name}";
              inherit value;
            }) self.packages.${system}.${pname}.passthru.tests;
        in
        (testsFrom "metafs")
        // {
          treefmt = treefmtEval.config.build.check self;

          selinux = import ./tests/screen/test.nix {
            inherit pkgs;
          };

          selinux-enforce = import ./tests/selinux-enforce/test.nix {
            inherit pkgs;
          };

          metafs = import ./tests/metafs/test.nix {
            inherit pkgs;
            metafs = self.packages.${system}.metafs;
          };

          # Deferred: integrate the metafs overlay into the SELinux boot path
          # and re-enable this once switching between configurations is wired
          # through the FUSE filesystem.
          # selinux-switch = import ./tests/selinux-switch/test.nix {
          #   inherit pkgs;
          # };
        }
      );
    };
}
