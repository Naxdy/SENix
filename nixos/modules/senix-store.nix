{ ... }: {
  config.security.selinux.modules.senix_store = {
    layer = "kernel";
    typeEnforcement = ''
      policy_module(senix_store)

      gen_require(`
        attribute file_type;
        type unlabeled_t;
        type init_t;
        type setfiles_t;
      ')

      type senix_meta_t;
      files_mountpoint(senix_meta_t);

      allow senix_meta_t senix_meta_t:filesystem associate;
      allow file_type senix_meta_t:filesystem associate;

      # Copy-up of an as-yet-unlabelled lower file (no `security.selinux` xattr)
      # presents an `unlabeled_t` label for association; this must not fail or
      # those opens/execs would be denied in enforcing mode.
      allow unlabeled_t senix_meta_t:filesystem associate;
    '';
  };
}
