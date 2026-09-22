{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib) mkOption types;

  programs = [
    "chromium"
    "google-chrome"
  ];

  anyProgramEnabled = lib.any (e: e) (map (e: config.programs.${e}.enable) programs);

  anyProgramSelinuxEnabled = lib.any (e: e) (map (e: config.programs.${e}.selinuxSupport) programs);
in
{
  options.programs = builtins.listToAttrs (
    map (name: {
      inherit name;
      value = {
        selinuxSupport = mkOption {
          type = types.bool;
          default = config.security.selinux.enable;
          defaultText = lib.literalExpression "config.security.selinux.enable";
          example = false;
          description = ''
            Whether to include appropriate SELinux modules within the system configuration.
          '';
        };
      }
      // lib.optionalAttrs (name == "chromium") {
        package = mkOption {
          type = types.package;
          default = pkgs.chromium;
          defaultText = lib.literalExpression "pkgs.chromium";
          description = ''
            The Chromium package to use for SELinux policies.
          '';
        };
      };
    }) programs
  );

  config = lib.mkIf (anyProgramEnabled && anyProgramSelinuxEnabled) {
    # Based on the refpolicy's policy/modules/apps/chromium.fc
    security.selinux.modules.chromium = {
      layer = "apps";
      fileContext = {
        storePaths =
          let
            shouldEnable = name: config.programs.${name}.enable && config.programs.${name}.selinuxSupport;
          in
          (lib.optionalAttrs (shouldEnable "google-chrome") {
            google-chrome = [
              config.programs.google-chrome.package
            ];
          })
          // (lib.optionalAttrs (shouldEnable "chromium") {
            chromium = [
              config.programs.chromium.package.passthru.browser
            ];
            chromium-wrapper = [
              config.programs.chromium.package
            ];
          });
        rules = {
          "@google-chrome@/bin/google-chrome-stable" = "--	gen_context(system_u:object_r:chromium_exec_t,s0)";

          "@google-chrome@/share/google/chrome/chrome" =
            "--	gen_context(system_u:object_r:chromium_exec_t,s0)";
          "@google-chrome@/share/google/chrome/chrome_sandbox" =
            "--	gen_context(system_u:object_r:chromium_sandbox_exec_t,s0)";
          "@google-chrome@/share/google/chrome/chrome-sandbox" =
            "--	gen_context(system_u:object_r:chromium_sandbox_exec_t,s0)";
          "@google-chrome@/share/google/chrome/google-chrome" =
            "--	gen_context(system_u:object_r:chromium_exec_t,s0)";
          "@google-chrome@/share/google/chrome/nacl_.*" =
            "--	gen_context(system_u:object_r:chromium_naclhelper_exec_t,s0)";
          "@google-chrome@/share/google/chrome/crashpad_handler" =
            "--	gen_context(system_u:object_r:chromium_exec_t,s0)";
          "@google-chrome@/share/google/chrome/chrome_crashpad_handler" =
            "--	gen_context(system_u:object_r:chromium_exec_t,s0)";

          "@google-chrome@/share/google/chrome-beta/chrome" =
            "--	gen_context(system_u:object_r:chromium_exec_t,s0)";
          "@google-chrome@/share/google/chrome-beta/chrome_sandbox" =
            "--	gen_context(system_u:object_r:chromium_sandbox_exec_t,s0)";
          "@google-chrome@/share/google/chrome-beta/chrome-sandbox" =
            "--	gen_context(system_u:object_r:chromium_sandbox_exec_t,s0)";
          "@google-chrome@/share/google/chrome-beta/google-chrome" =
            "--	gen_context(system_u:object_r:chromium_exec_t,s0)";
          "@google-chrome@/share/google/chrome-beta/nacl_helper_bootstrap" =
            "--	gen_context(system_u:object_r:chromium_naclhelper_exec_t,s0)";

          "@google-chrome@/share/google/chrome-unstable/chrome" =
            "--	gen_context(system_u:object_r:chromium_exec_t,s0)";
          "@google-chrome@/share/google/chrome-unstable/chrome_sandbox" =
            "--	gen_context(system_u:object_r:chromium_sandbox_exec_t,s0)";
          "@google-chrome@/share/google/chrome-unstable/chrome-sandbox" =
            "--	gen_context(system_u:object_r:chromium_sandbox_exec_t,s0)";
          "@google-chrome@/share/google/chrome-unstable/google-chrome" =
            "--	gen_context(system_u:object_r:chromium_exec_t,s0)";
          "@google-chrome@/share/google/chrome-unstable/nacl_helper_bootstrap" =
            "--	gen_context(system_u:object_r:chromium_naclhelper_exec_t,s0)";

          "@chromium-wrapper@/bin/chromium" = "--	gen_context(system_u:object_r:chromium_exec_t,s0)";
          "@chromium@/libexec/chromium/chromium" = "--	gen_context(system_u:object_r:chromium_exec_t,s0)";
          "@chromium@/libexec/chromium/chrome-sandbox" =
            "--	gen_context(system_u:object_r:chromium_sandbox_exec_t,s0)";
          "@chromium@/libexec/chromium/chrome_crashpad_handler" =
            "--	gen_context(system_u:object_r:chromium_exec_t,s0)";

          "HOME_DIR/\.cache/chromium(/.*)?" = "gen_context(system_u:object_r:chromium_xdg_cache_t,s0)";
          "HOME_DIR/\.cache/google-chrome(/.*)?" = "gen_context(system_u:object_r:chromium_xdg_cache_t,s0)";
          "HOME_DIR/\.cache/microsoft-edge(/.*)?" = "gen_context(system_u:object_r:chromium_xdg_cache_t,s0)";
          "HOME_DIR/\.config/chromium(/.*)?" = "gen_context(system_u:object_r:chromium_xdg_config_t,s0)";
          "HOME_DIR/\.config/google-chrome(/.*)?" = "gen_context(system_u:object_r:chromium_xdg_config_t,s0)";
          "HOME_DIR/\.config/microsoft-edge(/.*)?" =
            "gen_context(system_u:object_r:chromium_xdg_config_t,s0)";
        };
      };
    };
  };
}
