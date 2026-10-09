{ ... }:
let
  # Helper for more easily adding toggleable options under `config.(services|programs).<name>`
  # for different apps.
  mkSenixAppModule =
    {
      # Name of the option in nixpkgs
      name,
      # Category of the app, i.e. `programs` or `services`.
      category,
      # Name of the SELinux module.
      # If `null`, uses the same value as `name`
      moduleName ? null,
      # `fileContext` rules to add.
      # The substitution is `@${name}@`.
      rules,
      # Attribute set of additional paths to be added to `fileContext.storePaths`.
      extraPaths ? { },
      # Name of the default package in case a new package option should be added.
      # Some programs like chromium don't have a package option by default,
      # so this can be used to easily insert one.
      addPackageOption ? null,
      # Whether to also add the `enable` option itself, in case the program doesn't exist
      # in nixpkgs at all as an option.
      #
      # If this is set, `addPackageOption` must also be provided.
      addEnableOption ? false,
    }:
    let
      mName = if moduleName != null then moduleName else name;
    in
    {
      config,
      lib,
      options,
      ...
    }:
    let
      canEnable = (options.${category}.${name} ? enable) && (options.${category}.${name} ? package);

      module =
        {
          config,
          lib,
          pkgs,
          ...
        }:
        let
          inherit (lib) mkOption types;

          cfg = config.${category}.${name};
        in
        {
          options.${category}.${name} = {
            selinuxSupport = mkOption {
              type = types.bool;
              default = config.security.selinux.enable;
              defaultText = lib.literalExpression "config.security.selinux.enable";
              description = ''
                Whether to add appropriate SELinux rules required for this program to operate normally.
              '';
            };
          }
          // (lib.optionalAttrs (addPackageOption != null) {
            package = lib.mkPackageOption pkgs addPackageOption { };
          })
          // (lib.optionalAttrs addEnableOption {
            enable = lib.mkEnableOption name;
          });

          config = lib.mkMerge [
            (lib.mkIf (canEnable && cfg.enable && cfg.selinuxSupport) {
              security.selinux.modules.${mName} = {
                layer = lib.mkDefault "apps";
                fileContext = {
                  storePaths = extraPaths // {
                    ${name} = [
                      cfg.package
                    ];
                  };
                  inherit rules;
                };
              };
            })
            (lib.mkIf ((options.${category}.${name} ? enable) && (addPackageOption != null) && cfg.enable) {
              environment.systemPackages = [
                cfg.package
              ];
            })
          ];
        };
    in
    {
      imports = [
        module
      ];
    };

  mkServiceProgramModule =
    name:
    { config, lib, ... }:
    {
      imports = [
        (mkSenixAppModule {
          inherit name;
          category = "programs";
        })
        (mkSenixAppModule {
          inherit name;
          category = "services";
        })
      ];
    };

  helpers = {
    inherit mkSenixAppModule mkServiceProgramModule;
  };

  files = [
    "bubblewrap"
    "chromium"
    "docportal"
    "pipewire"
    "thunderbird"
  ];
in
{
  imports = map (e: import ./${e}.nix { inherit helpers; }) files;
}
