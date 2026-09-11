{ config, pkgs, ... }: {
  config.security.selinux.modules.libraries = {
    layer = "libraries";
    fileContext = {
      storePaths.lib = config.environment.systemPackages ++ [
        pkgs.glibc
        pkgs.coreutils
        pkgs.policycoreutils
        pkgs.libselinux
        pkgs.acl
        pkgs.attr
        pkgs.findutils
        pkgs.util-linux
        config.systemd.package
      ];
      rules = {
        #
        # /etc
        #
        "/etc/ld\.so\.cache" = "--	gen_context(system_u:object_r:ld_so_cache_t,s0)";
        "/etc/ld\.so\.preload" = "--	gen_context(system_u:object_r:ld_so_cache_t,s0)";
        "/etc/ld-musl-[^/]*\.path" = "--	gen_context(system_u:object_r:ld_so_cache_t,s0)";

        "/etc/ppp/plugins/rp-pppoe\.so" = "--	gen_context(system_u:object_r:lib_t,s0)";

        #
        # /opt
        #
        "@lib@/.*\.so" = "gen_context(system_u:object_r:lib_t,s0)";
        "@lib@/(.*/)?jre.*/.+\.so(\.[^/]*)*" = "--	gen_context(system_u:object_r:textrel_shlib_t,s0)";
        "@lib@/(.*/)?jre/.+\.jar" = "--	gen_context(system_u:object_r:lib_t,s0)";

        #
        # /usr
        #
        "@lib@/bin/ldconfig" = "--	gen_context(system_u:object_r:ldconfig_exec_t,s0)";

        "@lib@/lib" = "gen_context(system_u:object_r:lib_t,s0)";
        "@lib@/lib/.*" = "gen_context(system_u:object_r:lib_t,s0)";

        "@lib@/(.*/)?java/.+\.so(\.[^/]*)*" = "--	gen_context(system_u:object_r:textrel_shlib_t,s0)";
        "@lib@/(.*/)?java/.+\.jar" = "--	gen_context(system_u:object_r:lib_t,s0)";
        "@lib@/(.*/)?java/.+\.jsa" = "--	gen_context(system_u:object_r:lib_t,s0)";

        "@lib@/(.*/)?lib(/.*)?" = "gen_context(system_u:object_r:lib_t,s0)";
        "@lib@/(.*/)?lib64(/.*)?" = "gen_context(system_u:object_r:lib_t,s0)";

        "@lib@/lib/ld-[^/]*\.so(\.[^/]*)*" = "--	gen_context(system_u:object_r:ld_so_t,s0)";
        "@lib@/lib/(.*/)?ld-[^/]*\.so(\.[^/]*)?" = "--	gen_context(system_u:object_r:ld_so_t,s0)";

        "@lib@/(.*/)?nvidia/.+\.so(\..*)?" = "--	gen_context(system_u:object_r:textrel_shlib_t,s0)";

        "@lib@/lib/postfix/lib.*so.*" = "--	gen_context(system_u:object_r:lib_t,s0)";
        "@lib@/lib/altivec/libavcodec\.so(\.[^/]*)*" =
          "--	gen_context(system_u:object_r:textrel_shlib_t,s0)";
        "@lib@/lib/cedega/.+\.so(\.[^/]*)*" = "--	gen_context(system_u:object_r:textrel_shlib_t,s0)";
        "@lib@/lib/dovecot/(.*/)?lib.*\.so.*" = "--      gen_context(system_u:object_r:lib_t,s0)";
        "@lib@/lib/vlc/video_chroma/libi420_rgb_mmx_plugin\.so" =
          "--	gen_context(system_u:object_r:textrel_shlib_t,s0)";
        "@lib@/lib/vlc/codec/librealvideo_plugin\.so" =
          "--	gen_context(system_u:object_r:textrel_shlib_t,s0)";
        "@lib@/lib/vlc/codec/libdmo_plugin\.so" = "--	gen_context(system_u:object_r:textrel_shlib_t,s0)";
        "@lib@/lib/vlc/codec/librealaudio_plugin\.so" =
          "--	gen_context(system_u:object_r:textrel_shlib_t,s0)";
        "@lib@/lib/libtfmessbsp\.so(\.[^/]*)*" = "--	gen_context(system_u:object_r:textrel_shlib_t,s0)";
        "@lib@/lib/xorg/libGL\.so(\.[^/]*)*" = "--	gen_context(system_u:object_r:textrel_shlib_t,s0)";
        "@lib@/X11R6/lib/libGL\.so.*" = "--	gen_context(system_u:object_r:textrel_shlib_t,s0)";
        "@lib@/lib/libGL\.so(\.[^/]*)*" = "--	gen_context(system_u:object_r:textrel_shlib_t,s0)";
        "@lib@/lib/catalyst/libGL\.so(\.[^/]*)*" = "--	gen_context(system_u:object_r:textrel_shlib_t,s0)";
        "@lib@/lib/libADM5.*\.so(\.[^/]*)*" = "--	gen_context(system_u:object_r:textrel_shlib_t,s0)";
        "@lib@/lib/libatiadlxx\.so(\.[^/]*)*" = "--	gen_context(system_u:object_r:textrel_shlib_t,s0)";
        "@lib@/lib/win32/.*\.so(\.[^/]*)*" = "--	gen_context(system_u:object_r:textrel_shlib_t,s0)";

        "@lib@/lib/ADM_plugins/videoFilter/.*\.so(\.[^/]*)*" =
          "-- gen_context(system_u:object_r:textrel_shlib_t,s0)";

        "@lib@/(.*/)?lib(64)?(/.*)?/nvidia/.+\.so(\..*)?" =
          "-- gen_context(system_u:object_r:textrel_shlib_t,s0)";
        "@lib@/lib(/.*)?/nvidia/.+\.so(\..*)?" = "--	gen_context(system_u:object_r:textrel_shlib_t,s0)";
        "@lib@/lib/libsipphoneapi\.so.*" = "--	gen_context(system_u:object_r:textrel_shlib_t,s0)";
        "@lib@/lib/ati-fglrx/.+\.so(\..*)?" = "--	gen_context(system_u:object_r:textrel_shlib_t,s0)";
        "@lib@/lib/fglrx/.*\.so(\.[^/]*)*" = "--	gen_context(system_u:object_r:textrel_shlib_t,s0)";
        "@lib@/lib/libjs\.so.*" = "--	gen_context(system_u:object_r:textrel_shlib_t,s0)";
        "@lib@/lib/sse2/libx264\.so(\.[^/]*)*" = "--	gen_context(system_u:object_r:textrel_shlib_t,s0)";
        "@lib@/lib/systemd/libsystemd-shared-[0-9]+\.so.*" = "-- gen_context(system_u:object_r:lib_t,s0)";
        "@lib@/lib(/.*)?/libnvidia.+\.so(\.[^/]*)*" =
          "--	gen_context(system_u:object_r:textrel_shlib_t,s0)";
        "@lib@/lib(/.*)?/nvidia_drv.*\.so(\.[^/]*)*" =
          "--	gen_context(system_u:object_r:textrel_shlib_t,s0)";
        "@lib@/lib/nero/plug-ins/libMP3\.so(\.[^/]*)*" =
          "--	gen_context(system_u:object_r:textrel_shlib_t,s0)";
        "@lib@/lib/nvidia-graphics(-[^/]*/)?libGL(core)?\.so(\.[^/]*)*" =
          "-- gen_context(system_u:object_r:textrel_shlib_t,s0)";
        "@lib@/lib/nvidia-graphics(-[^/]*/)?libnvidia.*\.so(\.[^/]*)*" =
          "-- gen_context(system_u:object_r:textrel_shlib_t,s0)";
        "@lib@/lib/nvidia-graphics(-[^/]*/)?libXvMCNVIDIA\.so.*" =
          "-- gen_context(system_u:object_r:textrel_shlib_t,s0)";
        "@lib@/lib/nvidia/libGL(core)?\.so(\.[^/]*)*" =
          "--	gen_context(system_u:object_r:textrel_shlib_t,s0)";
        "@lib@/lib/xorg/modules/glesx\.so(\.[^/]*)*" =
          "--	gen_context(system_u:object_r:textrel_shlib_t,s0)";
        "@lib@/lib/security/pam_poldi\.so" = "--	gen_context(system_u:object_r:textrel_shlib_t,s0)";

        "@lib@/(local/)?.*\.so(\.[^/]*)*" = "--	gen_context(system_u:object_r:lib_t,s0)";
        "@lib@/(local/)?lib(64)?/wine/.+\.so" = "--	gen_context(system_u:object_r:textrel_shlib_t,s0)";
        "@lib@/(local/)?lib(64)?/(sse2/)?libfame-.*\.so.*" =
          "--	gen_context(system_u:object_r:textrel_shlib_t,s0)";
        "@lib@/NX/lib/libXcomp\.so.*" = "--	gen_context(system_u:object_r:textrel_shlib_t,s0)";
        "@lib@/NX/lib/libjpeg\.so.*" = "--	gen_context(system_u:object_r:textrel_shlib_t,s0)";

        "@lib@/X11R6/lib/libXvMCNVIDIA\.so.*" = "--	gen_context(system_u:object_r:textrel_shlib_t,s0)";

        "@lib@/lib/xorg/modules/drivers/fglrx_drv\.so(\.[^/]*)*" =
          "-- gen_context(system_u:object_r:textrel_shlib_t,s0)";
        "@lib@/lib/xorg/modules/drivers/nvidia_drv\.o" =
          "--	gen_context(system_u:object_r:textrel_shlib_t,s0)";
        "@lib@/lib/xorg/modules/extensions/nvidia(-[^/]*)?/libglx\.so(\.[^/]*)*" =
          "-- gen_context(system_u:object_r:textrel_shlib_t,s0)";
        "@lib@/lib/xorg/modules/extensions/libglx\.so(\.[^/]*)*" =
          "-- gen_context(system_u:object_r:textrel_shlib_t,s0)";
        "@lib@/x11R6/lib/modules/extensions/libglx\.so(\.[^/]*)*" =
          "-- gen_context(system_u:object_r:textrel_shlib_t,s0)";

        #
        # /var
        #
        "/var/cache/ldconfig(/.*)?" = "gen_context(system_u:object_r:ldconfig_cache_t,s0)";

        "/var/ftp/lib(64)?(/.*)?" = "gen_context(system_u:object_r:lib_t,s0)";
        "/var/ftp/lib(64)?/ld[^/]*\.so(\.[^/]*)*" = "--	gen_context(system_u:object_r:ld_so_t,s0)";

        "/var/lib/spamassassin/compiled/.*\.so.*" = "--	gen_context(system_u:object_r:lib_t,s0)";

        "/var/mailman/pythonlib(/.*)?/.+\.so(\..*)?" = "--	gen_context(system_u:object_r:lib_t,s0)";

        "/var/spool/postfix/lib(64)?(/.*)?" = "gen_context(system_u:object_r:lib_t,s0)";
        "/var/spool/postfix/usr(/.*)?" = "gen_context(system_u:object_r:lib_t,s0)";
        "/var/spool/postfix/lib(64)?/ld.*\.so.*" = "--	gen_context(system_u:object_r:ld_so_t,s0)";
      };
    };
  };
}
