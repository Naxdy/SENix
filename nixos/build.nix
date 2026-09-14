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

  policySrc = cfg.refpolicy.package.src;
  supportDir = "${policySrc}/policy/support";

  # The Reference Policy layer directories that exist in the source tree.
  refpolicyLayers = lib.attrNames (
    lib.filterAttrs (_: t: t == "directory") (builtins.readDir "${policySrc}/policy/modules")
  );
  refpolicyLayerFiles = lib.mapAttrs (
    layer: _: builtins.readDir "${policySrc}/policy/modules/${layer}"
  ) (lib.genAttrs refpolicyLayers (_: null));
  # Which Reference Policy layer a module belongs to (auto-detected by scanning
  # the source tree). Modules not present in the Reference Policy are reported
  # as `senix` — i.e. they are custom modules that must be appended to the
  # generated `modules.conf`.
  moduleLayer =
    name:
    let
      found = lib.filter (
        layer:
        let
          files = refpolicyLayerFiles.${layer};
        in
        builtins.hasAttr "${name}.te" files
        || builtins.hasAttr "${name}.if" files
        || builtins.hasAttr "${name}.fc" files
      ) refpolicyLayers;
    in
    if found == [ ] then "senix" else builtins.head found;
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

  # Materialize a module source to a store path, passing paths through and
  # writing raw declarations to a `writeText` file.
  materializeSource =
    content: filename:
    if lib.hasPrefix "/nix/store" content then content else pkgs.writeText filename content;

  # A derivation that homes every module's sources laid out beneath
  # `policy/modules/<layer>/`. `build.policy` overlays this onto the Reference
  # Policy source tree, so the huge per-module copy logic never has to appear in
  # a build phase (which would overflow ARG_MAX).
  moduleSourceDrv =
    let
      stubFc = pkgs.writeText "stub.fc" "";
    in
    pkgs.linkFarm "selinux-module-sources" (
      lib.flatten (
        map (
          name:
          let
            m = mods.${name};
            inherit (m) layer;
            isCustom = moduleLayer name == "senix";
            dir = "policy/modules/${layer}";
            te =
              if m.typeEnforcement != null then
                [
                  {
                    inherit dir;
                    name = "${dir}/${name}.te";
                    path = materializeSource m.typeEnforcement "${name}.te";
                  }
                ]
              else
                # Not overridden: keep the module's `.te` from the Reference Policy
                # tree (or let `make conf` generate it from `.te.in`).
                [ ];
            if_ =
              if m.interface != null then
                [
                  {
                    inherit dir;
                    name = "${dir}/${name}.if";
                    path = materializeSource m.interface "${name}.if";
                  }
                ]
              else if isCustom then
                # Custom modules don't have a `.if` in the Reference Policy tree;
                # the build requires one anyway. It must also be *documented*:
                # sedoctool.py only registers a module in modules.conf if its
                # XML carries a module-level `<summary>`, so an empty stub would
                # silently drop the module from the build. Provide a documented
                # stub, which the `all_layers` pipeline turns into a registered
                # (loadable) module with no manual modules.conf editing.
                [
                  {
                    inherit dir;
                    name = "${dir}/${name}.if";
                    path = pkgs.writeText "${name}.if" ''
                      ## <summary>
                      ## SENix custom module.
                      ## </summary>
                    '';
                  }
                ]
              else
                # Overridden built-in module: keep the Reference Policy `.if`.
                [ ];
            fc =
              if m.fileContext.source != null then
                [
                  {
                    inherit dir;
                    name = "${dir}/${name}.fc";
                    path = m.fileContext.source;
                  }
                ]
              else if m.fileContext.rules != { } then
                [
                  {
                    inherit dir;
                    name = "${dir}/${name}.fc";
                    path = pkgs.writeText "${name}.fc" (genFC m.fileContext + "\n");
                  }
                ]
              else if isCustom then
                # Custom modules don't have a `.fc` in the Reference Policy tree;
                # the build requires one, so provide an empty file.
                [
                  {
                    inherit dir;
                    name = "${dir}/${name}.fc";
                    path = stubFc;
                  }
                ]
              else
                # Overridden built-in module: keep the Reference Policy `.fc`.
                [ ];
          in
          te ++ if_ ++ fc
        ) moduleNames
      )
      ++ [
        # The `senix` layer that hosts modules which aren't part of the Reference
        # Policy. It must exist (with a metadata.xml) so `make conf` can build
        # policy.xml over it.
        {
          name = "policy/modules/senix/metadata.xml";
          path = pkgs.writeText "senix-metadata.xml" "<summary>SENix custom modules.</summary>";
        }
      ]
    );

  # Custom modules (not part of the Reference Policy) are detected by scanning
  # the source tree (never by their declared `layer`); they are registered by
  # `make conf`'s `all_layers` pipeline exactly like built-in modules.

  # Common make flags for the Reference Policy build (single line so they can
  # be interpolated directly into a `make` invocation).
  refpolicyTools = "CHECKPOLICY=${pkgs.checkpolicy}/bin/checkpolicy CHECKMODULE=${pkgs.checkpolicy}/bin/checkmodule SEMODULE=${pkgs.policycoreutils}/bin/semodule SEMOD_PKG=${pkgs.semodule-utils}/bin/semodule_package SEMOD_LNK=${pkgs.semodule-utils}/bin/semodule_link SEMOD_EXP=${pkgs.semodule-utils}/bin/semodule_expand DISTRO=nixos SYSTEMD=y UBAC=y";

  # The policy is built from the Reference Policy sources in full: every built-in
  # module is compiled, and any module declared in `config.security.selinux.modules`
  # is overlaid (taking precedence over the built-in module of the same name).
  policyDrv = pkgs.stdenv.mkDerivation {
    pname = "senix-policy";
    version = "0";

    src = policySrc;

    nativeBuildInputs = [
      pkgs.gnum4
      pkgs.python3
      pkgs.getopt
    ];

    configurePhase = ''
      runHook preConfigure

      # `make conf`'s `all_layers` scan auto-disovers the SENix-only modules
      # overlaid by `postPatch`, and - because every custom module ships a
      # documented `.if` stub (see `moduleSourceDrv`) - sedoctool.py registers
      # each one in modules.conf as a loadable module. No manual patching of
      # modules.conf is needed.
      make conf ''${makeFlags[@]}

      runHook postConfigure
    '';

    postPatch = ''
      # The store-backed source tree may be read-only; the Reference Policy
      # build writes generated files (.te/.if/.fc from .in, modules.conf, ...)
      # into it, so make it writable first.
      chmod -R u+w .
      # Overlay the SENix module sources onto the Reference Policy source tree:
      # a module with the same name+layer as a built-in overrides it (the files
      # are copied over it), while new modules are placed next to their layer
      # neighbours. Also adds the `senix` layer metadata.xml. `moduleSourceDrv`
      # is a `linkFarm`, so resolve (-L: dereference) and copy the actual file
      # contents - keeping symlinks would leave writable-looking paths that
      # actually point into the read-only /nix/store, so any in-place write
      # fails. The copies inherit the read-only store modes, so make them
      # writable too after copying.
      cp -aL ${moduleSourceDrv}/. .
      chmod -R u+w .
    '';

    makeFlags = [
      "CHECKPOLICY=${lib.getExe pkgs.checkpolicy}"
      "CHECKMODULE=${lib.getExe' pkgs.checkpolicy "checkmodule"}"
      "SEMODULE=${lib.getExe' pkgs.policycoreutils "semodule"}"
      "SEMOD_PKG=${lib.getExe' pkgs.semodule-utils "semodule_package"}"
      "SEMOD_LNK=${lib.getExe' pkgs.semodule-utils "semodule_link"}"
      "SEMOD_EXP=${lib.getExe' pkgs.semodule-utils "semodule_expand"}"
      "DESTDIR=${placeholder "out"}"
      "prefix=${placeholder "out"}"
      "DISTRO=nixos"
      "SYSTEMD=y"
      "UBAC=y"
      "TYPE=mcs"
    ]
    ++ lib.optional (cfg.policyVersion != null) "OUTPUT_POLICY=${toString cfg.policyVersion}"
    ++ lib.optional (cfg.policyVersion != null) "OUTPUT_MODULE=${toString cfg.policyVersion}";
  };
in
{
  options.security.selinux.build = {
    policy = mkOption {
      type = types.package;
      readOnly = true;
      default = policyDrv;
      description = ''
        The final, combined SELinux policy package built entirely from
        `config.security.selinux.modules`. It is a self-contained Reference
        Policy (base module plus every declared module) that is loaded at boot
        and activation, replacing the pre-built `pkgs.selinux-refpolicy` base.
      '';
    };
  };

  config = { };
}
