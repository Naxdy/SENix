{
  lib,
  ...
}:
let
  inherit (lib) mkOption types;
in
{
  options.security.selinux.build = {
    squashfs = mkOption {
      type = types.package;
      readOnly = true;
      description = ''
        The final SquashFS filesystem containing the file metadata for paths within the Nix store.
      '';
    };
    policy = mkOption {
      type = types.package;
      readOnly = true;
      description = ''
        The final SELinux policy to be loaded.
      '';
    };
  };

  config = {

  };
}
