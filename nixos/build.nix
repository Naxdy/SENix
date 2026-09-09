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
        The final SquashFS filesystem containing the SELinux file context / extended attribute metadata for paths within the Nix store.

        When `security.selinux.storeOverlay` is enabled, this filesystem is overlaid over `/nix/store` at runtime to supply labels that cannot be stored on the read-only store.
      '';
    };

    policy = mkOption {
      type = types.package;
      readOnly = true;
      description = ''
        The final, combined SELinux policy to be loaded at boot and activation.

        Composed of `security.selinux.policy` together with every compiled module in `security.selinux.modules`, the latter taking precedence.
      '';
    };

    modules = mkOption {
      type = types.attrsOf types.path;
      readOnly = true;
      description = ''
        The compiled policy modules (`*.pp`) derived from `security.selinux.modules`, keyed by module name.
      '';
    };
  };

  config = { };
}
