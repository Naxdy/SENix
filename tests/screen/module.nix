{
  pkgs,
  ...
}:
{
  config = {
    security.selinux = {
      enable = true;
      modules = {
        screen = {
          layer = "apps";
          typeEnforcement = builtins.readFile ./screen.te;
          interface = builtins.readFile ./screen.if;
          fileContext = {
            storePaths = {
              screen = [
                pkgs.screen
              ];
              tmux = [
                pkgs.tmux
              ];
            };
            rules = {
              "HOME_DIR/\\.config/tmux(/.*)?" = "gen_context(system_u:object_r:screen_home_t,s0)";
              "HOME_DIR/\\.screen(/.*)?	" = "gen_context(system_u:object_r:screen_home_t,s0)";
              "HOME_DIR/\\.screenrc" = "gen_context(system_u:object_r:screen_home_t,s0)";
              "HOME_DIR/\\.tmux\\.conf" = "gen_context(system_u:object_r:screen_home_t,s0)";
              "/run/screen(/.*)?" = "gen_context(system_u:object_r:screen_runtime_t,s0)";
              "/run/tmux(/.*)?" = "gen_context(system_u:object_r:screen_runtime_t,s0)";
              "@screen@/bin/screen.*" = "gen_context(system_u:object_r:screen_exec_t,s0)";
              "@tmux@/bin/tmux" = "gen_context(system_u:object_r:screen_exec_t,s0)";
            };
          };
        };
      };
    };
  };
}
