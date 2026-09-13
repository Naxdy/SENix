{ config, ... }: {
  # Minimal placeholder for the planned "store metadata filesystem" type.
  # Currently ONLY declares the type so we can experiment (mounting tmpfs with
  # `context=…senix_meta_t…` post-boot) without any of the role/user-fu that
  # the full senix design would need.
  config.security.selinux.modules.senix_store = {
    layer = "kernel";
    typeEnforcement = ''
      policy_module(senix_store)

      type senix_meta_t;
      files_type(senix_meta_t)
    '';
  };
}
