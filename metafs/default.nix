{
  craneLib,
}:
let
  cargoToml = builtins.fromTOML (builtins.readFile ./Cargo.toml);

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
    passthru.tests = {
      test = craneLib.cargoTest craneBuildArgs;

      clippy = craneLib.cargoClippy craneBuildArgs;
    };
  }
)
