{
  stdenv,
  glib,
  fetchurl,
  lib,
  libselinux,
  pkg-config,
  libsepol,
}:
stdenv.mkDerivation (finalAttrs: {
  pname = "restorecond";
  version = "3.11";

  src = fetchurl {
    url = "https://github.com/SELinuxProject/selinux/releases/download/${finalAttrs.version}/restorecond-${finalAttrs.version}.tar.gz";
    hash = "sha256-9AzlJG1CdGsi2+NjxDxuvSjQUbVo5MBtLewcS4qHpco=";
  };

  nativeBuildInputs = [
    pkg-config
  ];

  buildInputs = [
    libselinux
    glib
    libsepol
  ];

  makeFlags = [
    "PREFIX=$(out)"
    "SBINDIR=$(out)/bin"
    "ETCDIR=$(out)/etc"
    "INITDIR=$(out)/etc/rc.d/init.d"
    "SELINUXDIR=$(out)/etc/selinux"
    "AUTOSTARTDIR=$(out)/etc/xdg/autostart"
    "LOCALEDIR=$(out)/share/locale"
    "MAN5DIR=$(out)/share/man/man5"
    "SYSTEMDSYSTEMUNITDIR=$(out)/lib/systemd/system"
    "SYSTEMDUSERUNITDIR=$(out)/lib/systemd/user"
  ];

  # Restorecond ships its own systemd services, but they don't work for
  # us ootb, and due to the amount of modifications we need to make
  # it's preferable to just use the Nix module system instead.
  #
  # To prevent users from accidentally enabling the upstream services,
  # e.g. via `config.systemd.packages`, we get rid of them here.
  postInstall = ''
    rm -rf $out/lib
  '';

  meta = {
    description = "SELinux automatic relabeling daemon";
    platforms = lib.platforms.linux;
    license = lib.licenses.gpl2Plus;
    mainProgram = "restorecond";
    maintainers = [
      lib.maintainers.naxdy
    ];
  };
})
