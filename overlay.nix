final: prev:
let
  inherit (final) lib;
in
{
  restorecond = final.callPackage ./pkgs/restorecond { };

  libselinux =
    if (lib.versionOlder prev.libselinux.version "3.11") then
      (prev.libselinux.overrideAttrs (
        old:
        let
          version = "3.11";
        in
        {
          inherit version;

          src = final.fetchurl {
            url = "https://github.com/SELinuxProject/selinux/releases/download/${version}/libselinux-${version}.tar.gz";
            hash = lib.fakeHash;
          };
        }
      ))
    else
      prev.libselinux;
}
