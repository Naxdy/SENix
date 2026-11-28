{
  crane,
  stdenv,
  lib,
  pkgs,
}:
let
  craneLib = (crane.mkLib pkgs).overrideToolchain (
    p:
    let
      targetToolchain = p.fenix.targets.${stdenv.hostPlatform.rust.rustcTargetSpec}.stable;

      toolchain = p.fenix.stable;
    in
    p.fenix.combine [
      toolchain.cargo
      toolchain.clippy
      toolchain.rust-src
      targetToolchain.rust-std
    ]
  );

  cargoWorkspaceToml = fromTOML (builtins.readFile ./Cargo.toml);

  craneArgs = {
    pname = "senix";
    version = cargoWorkspaceToml.workspace.package.version;

    src = lib.fileset.toSource {
      root = ./.;
      fileset = lib.fileset.unions [
        (craneLib.fileset.commonCargoSources ./pkgs/metafs)
        (craneLib.fileset.commonCargoSources ./.)
        # Parse fixtures are not Rust sources, so `commonCargoSources` drops
        # them; `include_str!` needs them at compile time.
        ./pkgs/sepol2nix/tests
      ];
    };
  };

  cargoArtifacts = craneLib.buildDepsOnly craneArgs;

  craneBuildArgs = craneArgs // {
    inherit cargoArtifacts;
  };

  mkSenixPackage =
    { pname, ... }@args:
    let
      packageArgs = craneBuildArgs // {
        cargoExtraArgs = "-p ${pname}";
      };
    in
    craneLib.buildPackage (
      packageArgs
      // args
      // {
        passthru.tests = {
          # The test suite evaluates generated expressions, so it needs Nix.
          test = craneLib.cargoTest (packageArgs // { nativeBuildInputs = [ pkgs.nix ]; });

          clippy = craneLib.cargoClippy packageArgs;
        };
      }
    );
in
{
  metafs =
    let
      cargoToml = fromTOML (builtins.readFile ./pkgs/metafs/Cargo.toml);
    in
    mkSenixPackage {
      pname = "metafs";
      meta.mainProgram = "metafs";

      # Ship metafs also as the `mount(8)` FUSE helper under the fstype-specific
      # name. mount(8) resolves helpers as `mount.<fstype>` through its
      # compiled-in search path and prefers the specific name over the generic
      # `mount.fuse`, enabling a plain `mount -t fuse.metafs ...` from fstab.
      postInstall = ''
        ln -s "$out/bin/${cargoToml.package.name}" "$out/bin/mount.fuse.${cargoToml.package.name}"
      '';
    };

  sepol2nix = mkSenixPackage {
    pname = "sepol2nix";
  };
}
