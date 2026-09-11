{ ... }: {
  # Overrides the Reference Policy's `corecommands.fc`. The upstream module
  # assigns `bin_t` to `/usr/bin`, `/usr/sbin`, `/usr/libexec` and various /etc
  # scripts; we mirror those rules with `/nix/store` globs (the store is the
  # NixOS analogue of `/usr`) so any executable installed there is labeled
  # without declaring it. `corecommands.te` stays untouched.
  config.security.selinux.modules.corecommands = {
    layer = "kernel";
    fileContext = {
      rules = {
        # Catch-all for the store (the NixOS analogue of `/usr`), so files not
        # matched by the more specific `bin_t`/`lib_t`/per-package rules below
        # get a readable type instead of falling to the default/unlabeled. The
        # specific rules come later in the fc and win via last-match-wins.
        "/nix/store(/.*)?" = "--	gen_context(system_u:object_r:usr_t,s0)";
        # Store executables.
        "/nix/store/.*/bin(/.*)?" = "--	gen_context(system_u:object_r:bin_t,s0)";
        "/nix/store/.*/sbin(/.*)?" = "--	gen_context(system_u:object_r:bin_t,s0)";
        "/nix/store/.*/libexec(/.*)?" = "--	gen_context(system_u:object_r:bin_t,s0)";
        # Shells.
        "/nix/store/.*/bin/(bash|dash|sh|ksh|mksh|tcsh|fish|sash|yash|nologin|sesh|scponly)(\.[0-9]+)?$" =
          "--	gen_context(system_u:object_r:shell_exec_t,s0)";

        # FHS paths still relabeled by `setfiles` on the non-store root.
        "/opt/(.*/)?libexec(/.*)?" = "gen_context(system_u:object_r:bin_t,s0)";
        "/dev/MAKEDEV" = "--	gen_context(system_u:object_r:bin_t,s0)";

        "/etc/acpi/actions(/.*)?" = "gen_context(system_u:object_r:bin_t,s0)";
        "/etc/cron\.(daily|hourly|weekly|monthly)(/.*)?" = "gen_context(system_u:object_r:bin_t,s0)";
        "/etc/dhcp/dhclient\.d(/.*)?" = "gen_context(system_u:object_r:bin_t,s0)";
        "/etc/dhcp/dhclient-(enter|exit)-hooks\.d(/.*)?" = "--	gen_context(system_u:object_r:bin_t,s0)";
        "/etc/pm/power\.d(/.*)?" = "gen_context(system_u:object_r:bin_t,s0)";
        "/etc/pm/sleep\.d(/.*)?" = "gen_context(system_u:object_r:bin_t,s0)";
        "/etc/kde/env(/.*)?" = "gen_context(system_u:object_r:bin_t,s0)";
        "/etc/kde/shutdown(/.*)?" = "gen_context(system_u:object_r:bin_t,s0)";
        "/etc/mail/make" = "--	gen_context(system_u:object_r:bin_t,s0)";
        "/etc/avahi/.*\.action" = "--	gen_context(system_u:object_r:bin_t,s0)";
        "/etc/letsencrypt/renewal-hooks/.*" = "--	gen_context(system_u:object_r:bin_t,s0)";
      };
    };
  };
}
