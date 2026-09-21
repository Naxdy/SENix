{ ... }: {
  config.security.selinux.modules.miscfiles = {
    layer = "system";
    fileContext = {
      rules = {
        #
        # /etc
        #
        "/etc/avahi/etc/localtime" = "--	gen_context(system_u:object_r:locale_t,s0)";
        "/etc/httpd/alias/[^/]*\.db(\.[^/]*)*" = "-- gen_context(system_u:object_r:cert_t,s0)";
        "/etc/httpd/conf/ssl(/.*)?" = "--	gen_context(system_u:object_r:tls_privkey_t,s0)";
        "/etc/httpd/conf/ssl/.*\.crt" = "--	gen_context(system_u:object_r:cert_t,s0)";
        "/etc/letsencrypt/archive/[^/]+/privkey.*" = "--	gen_context(system_u:object_r:tls_privkey_t,s0)";
        "/etc/letsencrypt/keys(/.*)?" = "gen_context(system_u:object_r:tls_privkey_t,s0)";
        "/etc/localtime" = "--	gen_context(system_u:object_r:locale_t,s0)";
        "/etc/pki(/.*)?" = "gen_context(system_u:object_r:cert_t,s0)";
        "/etc/pki/.*/private(/.*)?" = "gen_context(system_u:object_r:tls_privkey_t,s0)";
        "/etc/ssl(/.*)?" = "gen_context(system_u:object_r:cert_t,s0)";
        "/etc/ssl/private(/.*)?" = "gen_context(system_u:object_r:tls_privkey_t,s0)";
        "/etc/timezone" = "--	gen_context(system_u:object_r:locale_t,s0)";

        #
        # /srv
        #
        "/srv/([^/]*/)?ftp(/.*)?" = "gen_context(system_u:object_r:public_content_t,s0)";
        "/srv/([^/]*/)?rsync(/.*)?" = "gen_context(system_u:object_r:public_content_t,s0)";

        #
        # /usr
        #
        "/nix/store/[^/]+/(.*/)?man" = "-d	gen_context(system_u:object_r:man_t,s0)";
        "/nix/store/[^/]+/(.*/)?man/.*" = "gen_context(system_u:object_r:man_t,s0)";

        "/nix/store/[^/]+/lib/locale(/.*)?" = "gen_context(system_u:object_r:locale_t,s0)";

        "/nix/store/[^/]+/lib/perl5/man(/.*)?" = "gen_context(system_u:object_r:man_t,s0)";

        "/nix/store/[^/]+/local/share/fonts(/.*)?" = "gen_context(system_u:object_r:fonts_t,s0)";

        "/nix/store/[^/]+/share/fonts(/.*)?" = "gen_context(system_u:object_r:fonts_t,s0)";
        "/nix/store/[^/]+/share/ghostscript/fonts(/.*)?" = "gen_context(system_u:object_r:fonts_t,s0)";
        "/nix/store/[^/]+/share/texmf[^/]*/fonts(/.*)?" = "gen_context(system_u:object_r:fonts_t,s0)";
        "/nix/store/[^/]+/share/X11/fonts(/.*)?" = "gen_context(system_u:object_r:fonts_t,s0)";

        "/nix/store/[^/]+/share/locale(/.*)?" = "gen_context(system_u:object_r:locale_t,s0)";
        "/nix/store/[^/]+/share/X11/locale(/.*)?" = "gen_context(system_u:object_r:locale_t,s0)";
        "/nix/store/[^/]+/share/zoneinfo(/.*)?" = "gen_context(system_u:object_r:locale_t,s0)";

        "/nix/store/[^/]+/share/ssl/certs(/.*)?" = "gen_context(system_u:object_r:cert_t,s0)";
        "/nix/store/[^/]+/share/ssl/private(/.*)?" = "gen_context(system_u:object_r:tls_privkey_t,s0)";

        "/nix/store/[^/]+/X11R6/lib/X11/fonts(/.*)?" = "gen_context(system_u:object_r:fonts_t,s0)";

        #
        # /var
        #
        "/var/ftp(/.*)?" = "gen_context(system_u:object_r:public_content_t,s0)";

        "/var/lib/texmf(/.*)?" = "gen_context(system_u:object_r:tetex_data_t,s0)";

        "/var/cache/fontconfig(/.*)?" = "gen_context(system_u:object_r:fonts_cache_t,s0)";
        "/var/cache/fonts(/.*)?" = "gen_context(system_u:object_r:tetex_data_t,s0)";
        "/var/cache/man(/.*)?" = "gen_context(system_u:object_r:man_cache_t,s0)";

        "/var/named/chroot/etc/pki(/.*)?" = "gen_context(system_u:object_r:cert_t,s0)";

        "/var/spool/abrt-upload(/.*)?" = "gen_context(system_u:object_r:public_content_rw_t,s0)";
        "/var/spool/texmf(/.*)?" = "gen_context(system_u:object_r:tetex_data_t,s0)";
      };
    };
  };
}
