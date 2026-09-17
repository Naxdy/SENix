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
    src = mkOption {
      type = types.package;
      default = pkgs.fetchFromGitHub {
        owner = "SELinuxProject";
        repo = "refpolicy";
        rev = "2a1d069a8e9820ced0087efad43ddba6acf3dabf";
        hash = "sha256-q+KfyRJC10N/iKozNFYJ2GysD6bzZs2+eh9LKLYsgX4=";
      };
      defaultText = "Refpolicy source.";
      description = ''
        The source code for the SELinux refpolicy to be used as a base for the declarative policy.
      '';
    };
  };
}
