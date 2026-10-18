{ lib, ... }: {
  config.security.selinux.modules.policykit.typeEnforcement = lib.mkAfter ''
    seutil_read_config(policykit_t)
    init_get_generic_units_status(policykit_t)
  '';
}
