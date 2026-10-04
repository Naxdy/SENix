{ config, lib, ... }: {
  config.security.selinux = {
    exclusions.etc = [
      "selinux/config"
      "selinux/targeted/seusers"
      "selinux/targeted/contexts/default_contexts"
      "selinux/targeted/contexts/default_type"
      "selinux/targeted/contexts/failsafe_context"
      "selinux/targeted/contexts/users"
    ];

    modules.files = {
      layer = "kernel";
      fileContext = {
        storePaths = {
          etc = lib.unique (
            builtins.filter (lib.hasPrefix "/nix/store") (
              lib.mapAttrsToList (_: value: lib.removeSuffix "/*" value.source) (
                builtins.removeAttrs config.environment.etc config.security.selinux.exclusions.etc
              )
            )
          );
        };
        rules = {
          "@etc@(/.*)?" = "gen_context(system_u:object_r:etc_t,s0)";

          "/nix" = "-d	gen_context(system_u:object_r:usr_t,s0)";
          "/nix/store" = "-d	gen_context(system_u:object_r:usr_t,s0)";

          # Root-level store entries (every store path basename is
          # `<hash>-<name>`), which the base module's rules cover only with a
          # directory flag plus a slashed-content glob. Files that a
          # derivation emits directly at the store root — e.g. the NixOS
          # fontconfig module's generated `fc-*.conf` and `fonts.conf` —
          # would otherwise fall through to the `/.* → default_t` catch-all
          # and be unreadable by anything (keepassxc's fontconfig setup was
          # the first manifestation).
          "/nix/store/[^/]+" = "gen_context(system_u:object_r:usr_t,s0)";

          "/usr" = "-d	gen_context(system_u:object_r:usr_t,s0)";

          # NixOS keeps a real `/lib64` directory (holding the binary-compat
          # `ld-linux-x86-64.so.2` link), unlike the FHS's symlink to
          # `/usr/lib64`, so it needs its own rule — `systemd-tmpfiles` creates
          # the loader link there and everything without a rule hits the
          # reference policy's `/.* → default_t` catch-all.
          "/lib64(/.*)?" = "gen_context(system_u:object_r:lib_t,s0)";

          # NixOS's system profile pointers. Everything resolves them — units,
          # generators, `mount`, `journalctl`, activation scripts, tooling — and
          # they are created by the initrd's activation stage, i.e. before the
          # policy is active, so without a rule they keep the tmpfs fallback
          # label and are unreadable. Give them the generic `/run` content type,
          # which is what a symlink created here later (`nixos-rebuild switch`)
          # inherits from `/run` anyway.
          "/run/booted-system" = "-l	gen_context(system_u:object_r:var_run_t,s0)";
          "/run/current-system" = "-l	gen_context(system_u:object_r:var_run_t,s0)";

          # Systemd's per-unit credential stores (`ImportCredential=`, `LoadCredential=`).
          # PID1 creates the tree itself, via `mkdir_label()` and — after mounting each
          # unit's credential tmpfs — `label_fix_full()` with the mount path as the
          # file-contexts lookup key, i.e. it expects the policy to carry a label for
          # it. Without one every directory in the tree keeps the generic `tmpfs_t`
          # fallback: the top-level one because PID1 creates it in the initrd, before
          # the policy is active, and the per-unit ones because they are `tmpfs`
          # mount roots (`fs_use_trans tmpfs`). `tmpfs_t` directories may not be
          # traversed by anything, so even the services importing their own
          # credentials are denied `search` on them.
          #
          # Label the tree like the rest of the unlabelled `/run` content — which is
          # what it inherits from `/run` itself on a boot where the policy is active
          # when PID1 creates it — so that it is searchable by every domain, as
          # systemd's credential design requires.
          "/run/credentials(/.*)?" = "gen_context(system_u:object_r:var_run_t,s0)";

          # The Nix daemon's state (`/nix/var/nix/{db,profiles,gcroots,…}`) is
          # program variable data — and the GC roots are symlinks into the
          # store that `systemd-tmpfiles` (re)creates. Without a rule these
          # paths hit the reference policy's `/.* → default_t` catch-all, which
          # is neither a meaningful label nor one tmpfiles may manage.
          "/nix/var(/.*)?" = "gen_context(system_u:object_r:var_lib_t,s0)";
        };
      };
    };
  };
}
