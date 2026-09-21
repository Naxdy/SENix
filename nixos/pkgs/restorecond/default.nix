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
  version = "3.10";

  src = fetchurl {
    url = "https://github.com/SELinuxProject/selinux/releases/download/${finalAttrs.version}/restorecond-${finalAttrs.version}.tar.gz";
    hash = "sha256-oa5kCE1KndVQZpMBzEVoc4efSf539x7i/Kn506FmRqA=";
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
