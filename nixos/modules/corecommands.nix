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
        # Store executables. No `--` flag: store `bin/`, `sbin/` and `libexec/`
        # entries are frequently *symlinks* (`bin/fsck.ext4` → `fsck`), and
        # `--` restricts the rule to regular files, so those symlinks fall
        # through to the `/nix/store/.*` catch-all and end up with the generic
        # `usr_t` — a label whose `lnk_file` permissions the systemd generators
        # (resolving executables off `PATH`) are not granted.
        "/nix/store/.*/bin(/.*)?" = "gen_context(system_u:object_r:bin_t,s0)";
        "/nix/store/.*/sbin(/.*)?" = "gen_context(system_u:object_r:bin_t,s0)";
        "/nix/store/.*/libexec(/.*)?" = "gen_context(system_u:object_r:bin_t,s0)";
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
