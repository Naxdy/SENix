{
  helpers,
}:
{
  config,
  lib,
  pkgs,
  ...
}:
{
  imports = [
    (helpers.mkSenixAppModule {
      name = "chromium";
      addPackageOption = "chromium";
      category = "programs";
      extraPaths = {
        chromium-unwrapped = [
          config.programs.chromium.package.passthru.browser
        ];
      };
      rules = {
        "@chromium@/bin/chromium" = "--	gen_context(system_u:object_r:chromium_exec_t,s0)";
        "@chromium-unwrapped@/libexec/chromium/chromium" =
          "--	gen_context(system_u:object_r:chromium_exec_t,s0)";
        "@chromium-unwrapped@/libexec/chromium/chrome-sandbox" =
          "--	gen_context(system_u:object_r:chromium_sandbox_exec_t,s0)";
        "@chromium-unwrapped@/libexec/chromium/chrome_crashpad_handler" =
          "--	gen_context(system_u:object_r:chromium_exec_t,s0)";
      };
    })
    (helpers.mkSenixAppModule {
      name = "google-chrome";
      category = "programs";
      moduleName = "chromium";
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
      };
    })
  ];
}
