{
  crane,
  stdenv,
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

  cargoToml = fromTOML (builtins.readFile ./Cargo.toml);

  craneArgs = {
    pname = cargoToml.package.name;
    version = cargoToml.package.version;

    src = craneLib.cleanCargoSource ./.;
  };

  cargoArtifacts = craneLib.buildDepsOnly craneArgs;

  craneBuildArgs = craneArgs // {
    inherit cargoArtifacts;
  };
in
craneLib.buildPackage (
  craneBuildArgs
  // {
    # Ship metafs also as the `mount(8)` FUSE helper under the fstype-specific
    # name. mount(8) resolves helpers as `mount.<fstype>` through its
    # compiled-in search path and prefers the specific name over the generic
    # `mount.fuse`, enabling a plain `mount -t fuse.metafs ...` from fstab.
    postInstall = ''
      ln -s "$out/bin/${cargoToml.package.name}" "$out/bin/mount.fuse.${cargoToml.package.name}"
    '';

    passthru.tests = {
      test = craneLib.cargoTest craneBuildArgs;

      clippy = craneLib.cargoClippy craneBuildArgs;
    };
  }
)
