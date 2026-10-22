{ ... }: {
  config.security.selinux.modules.senix_store = {
    layer = "kernel";
    interface = {
      summary = "SENix custom module.";
      required = ''
        Required in the base module: this module declares the `fs_use_xattr
        fuse;` statement, which is only valid in the base (checkmodule rejects
        it in a loadable module), routing SELinux labels through the metafs
        overlay.
      '';
    };
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

      # SELinux decides whether a filesystem handles `security.selinux` labels
      # through xattrs by consulting the policy's `fs_use` table
      # (`security_fs_use()`, `OCON_FSUSE`). FUSE is not declared there by the
      # reference policy, so it falls back to genfs — `setxattr("security.selinux")`
      # then short-circuits with `EOPNOTSUPP` in `selinux_inode_setxattr` before
      # ever reaching the daemon (the `seclabel` mount option is, by its own
      # comments, "eaten and completely ignored"). Declaring FUSE as xattr-based
      # is what routes labels through the metafs overlay: systemd's post-switch
      # relabel then stores contexts into the in-memory xattr map.
      fs_use_xattr fuse gen_context(system_u:object_r:fs_t,s0);

      allow senix_meta_t senix_meta_t:filesystem associate;
      allow file_type senix_meta_t:filesystem associate;
      allow unlabeled_t senix_meta_t:filesystem associate;
    '';
  };
}
