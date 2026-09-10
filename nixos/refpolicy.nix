{
  lib,
  pkgs,
  ...
}:
let
  inherit (lib) mkOption types;
in
{
  options.security.selinux.refpolicy = {
    package = mkOption {
      type = types.package;
      default = pkgs.selinux-refpolicy.override { policyVersion = "refpolicy"; };
      defaultText = lib.literalExpression ''
        pkgs.selinux-refpolicy.override { policyVersion = "refpolicy"; }
      '';
      description = ''
        The SELinux refpolicy source to use as the base of the declarative policy.
      '';
    };
  };
}
