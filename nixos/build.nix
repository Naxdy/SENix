{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib) mkOption types;

  cfg = config.security.selinux;
  mods = cfg.modules;
  moduleNames = builtins.attrNames mods;

  refpolicy = cfg.policy;
  includeDir = "${refpolicy}/include";

  # Expand `@attr@` placeholders in file context rules using their store paths.
  expandRule =
    fileContext: key: value:
    let
      m = builtins.match "@([^@]+)@(.*)" key;
    in
    if m == null then
      [
        "${key}\t${value}"
      ]
    else
      let
        attr = builtins.elemAt m 0;
        rest = builtins.elemAt m 1;
      in
      map (sp: "${toString sp}${rest}\t${value}") fileContext.storePaths.${attr};

  genFC =
    fileContext:
    lib.concatStringsSep "\n" (
      lib.concatLists (lib.mapAttrsToList (expandRule fileContext) fileContext.rules)
    );

  # `.fc` content for a module, or `null` when the module declares no rules.
  moduleFC = m: if m.fileContext.rules == { } then null else genFC m.fileContext;
  # Bake the module's `.te`/`.if`/`.fc` sources into the build directory.
  writeModule =
    name: m:
    let
      fc = moduleFC m;
    in
    ''
      cat > ${name}.te <<'SENIX_SOURCE_EOF'
      ${if m.typeEnforcement != null then m.typeEnforcement else "policy_module(${name})\n"}
      SENIX_SOURCE_EOF
      ${lib.optionalString (m.interface != null) ''
        cat > ${name}.if <<'SENIX_SOURCE_EOF'
        ${m.interface}
        SENIX_SOURCE_EOF
      ''}
      ${lib.optionalString (fc != null) ''
        cat > ${name}.fc <<'SENIX_SOURCE_EOF'
        ${fc}
        SENIX_SOURCE_EOF
      ''}
    '';

  writeModules = lib.concatStrings (lib.mapAttrsToList writeModule mods);

  installModules = lib.concatStrings (
    map (name: ''
      install -D -m 0644 ${name}.pp "$out/${name}.pp"
    '') moduleNames
  );

  modulesDrv = pkgs.stdenv.mkDerivation {
    pname = "selinux-policy-modules";
    version = "1";
    dontUnpack = true;

    nativeBuildInputs = [
      pkgs.gnum4
      pkgs.checkpolicy
      pkgs.semodule-utils
      pkgs.gawk
      pkgs.gnused
    ];

    buildInputs = [
      refpolicy
    ];

    buildPhase = ''
      runHook preBuild

      set -euo pipefail

      include=${includeDir}

      ${writeModules}

      # Declared modules take precedence over the base policy: exclude any base
      # `.if` file whose module we are overriding, so its interfaces are not
      # redefined by our own module's `.if` (which would abort the M4 run).
      excluded=" ${toString moduleNames} "
      header_interfaces=""

      for d in "$include"/*; do
        if [ -d "$d" ] && [ "$(basename "$d")" != support ]; then
          for f in "$d"/*.if; do
            base=$(basename "$f" .if)
            case "$excluded" in
              *" $base "*) ;;
              *) header_interfaces="$header_interfaces $f" ;;
            esac
          done
        fi
      done

      make -f "$include/Makefile" \
        NAME=${cfg.type} \
        SHAREDIR="${refpolicy}/share/selinux" \
        HEADERDIR="$include" \
        CHECKMODULE=${pkgs.checkpolicy}/bin/checkmodule \
        SEMOD_PKG=${pkgs.semodule-utils}/bin/semodule_package \
        SEMODULE=${pkgs.policycoreutils}/bin/semodule \
        M4=${pkgs.gnum4}/bin/m4 \
        AWK=${pkgs.gawk}/bin/gawk \
        SED=${pkgs.gnused}/bin/sed \
        header_interfaces="$header_interfaces" \
        all

      ${installModules}

      runHook postBuild
    '';
  };
in
{
  options.security.selinux.build = {
    squashfs = mkOption {
      type = types.package;
      readOnly = true;
      description = ''
        The final SquashFS filesystem containing the SELinux file context / extended attribute metadata for paths within the Nix store.

        When `security.selinux.storeOverlay` is enabled, this filesystem is overlaid over `/nix/store` at runtime to supply labels that cannot be stored on the read-only store.
      '';
    };

    policy = mkOption {
      type = types.package;
      readOnly = true;
      description = ''
        The final, combined SELinux policy to be loaded at boot and activation.

        Composed of `security.selinux.policy` together with every compiled module in `security.selinux.modules`, the latter taking precedence.
      '';
    };

    modules = mkOption {
      type = types.package;
      readOnly = true;
      default = modulesDrv;
      description = ''
        A derivation producing all compiled policy modules (`*.pp`) derived from `security.selinux.modules`.
      '';
    };
  };
}
