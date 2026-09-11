{ ... }: {
  config.security.selinux.modules.nix.fileContext = {
    rules = {
      "/nix" = "-d  gen_context(system_u:object_r:usr_t,s0)";
      "/nix/store" = "-d  gen_context(system_u:object_r:usr_t,s0)";
      "/nix/store/.*" = "gen_context(system_u:object_r:usr_t,s0)";
    };
  };
}
