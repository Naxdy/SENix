{ ... }: {
  # Overrides the Reference Policy's `libraries.fc`. Instead of expanding an
  # `@lib@` marker against declared store paths, we use glob patterns over
  # `/nix/store` so that *any* package installed there is labeled without having
  # to enumerate it (this also covers packages added at runtime via `nix install`
  # and avoids referencing main-system derivations — which would otherwise pull
  # them into the initrd and, via the policy, cause evaluation recursion).
  #
  # The store overlay applies these rules onto the writable upper at boot and on
  # `nixos-rebuild switch`; the underlying `/nix/store` is never written to, so
  # it stays immutable.
  config.security.selinux.modules.libraries = {
    layer = "system";
    fileContext = {
      rules = {
        # Shared libraries. The `usr_t` catch-all and executable (`bin_t`) rules
        # live in `corecommands.nix` (the store analogue of `/usr`); only the
        # library-specific rules belong here.
        "/nix/store/.*/lib(/.*)?" = "--	gen_context(system_u:object_r:lib_t,s0)";
        "/nix/store/.*/lib64(/.*)?" = "--	gen_context(system_u:object_r:lib_t,s0)";
        "/nix/store/.*/lib/ld-[^/]*\.so(\.[0-9]+)*" = "--	gen_context(system_u:object_r:ld_so_t,s0)";
        "/nix/store/.*/bin/ldconfig" = "--	gen_context(system_u:object_r:ldconfig_exec_t,s0)";

        # FHS /etc + /var library paths (applied by the relabel's `setfiles` on
        # the non-store root). In NixOS these resolve into the store, which is
        # labeled above.
        "/etc/ld\.so\.cache" = "--	gen_context(system_u:object_r:ld_so_cache_t,s0)";
        "/etc/ld\.so\.preload" = "--	gen_context(system_u:object_r:ld_so_cache_t,s0)";
        "/etc/ld-musl-[^/]*\.path" = "--	gen_context(system_u:object_r:ld_so_cache_t,s0)";
        "/var/cache/ldconfig(/.*)?" = "gen_context(system_u:object_r:ldconfig_cache_t,s0)";
        "/var/lib/ldconfig(/.*)?" = "gen_context(system_u:object_r:ldconfig_cache_t,s0)";
      };
    };
  };
}
