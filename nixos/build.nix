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

  policySrc = cfg.refpolicy.src;

  # The `selinux` Python bindings, needed by the Reference Policy's
  # `validate-appconfig.py`. libselinux 3.11's SWIG typemaps still call the
  # Python 2-era `PyString_FromString`, which Python 3.12 removed; alias it to
  # the equivalent `PyUnicode_FromString`.
  pythonBindings = pkgs.python3.withPackages (ps: [
    (ps.libselinux.overrideAttrs (old: {
      env = (old.env or { }) // {
        NIX_CFLAGS_COMPILE =
          (old.env.NIX_CFLAGS_COMPILE or "") + " -DPyString_FromString=PyUnicode_FromString";
      };
    }))
  ]);

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

  # Whether the generated `senix` layer will actually hold a module. `make conf`
  # scans every `policy/modules/*` directory and `segenxml.py` errors out on a
  # layer that contains no `.te` files, so the layer directory (and its
  # `metadata.xml`) must only be materialized when there is at least one module
  # whose sources land in it.
  hasSenixModules = lib.any (
    name: mods.${name}.layer == "senix" && mods.${name}.typeEnforcement != null
  ) moduleNames;

  # Expand `@attr@` placeholders in file context rules using their store paths.
  expandRule =
    fileContext: key: value:
    let
      expandValues =
        key: value:
        if builtins.typeOf value == "list" then (map (e: "${key}\t${e}") value) else [ "${key}\t${value}" ];

      m = builtins.match "@([^@]+)@(.*)" key;
    in
    if m == null then
      expandValues key value
    else
      let
        attr = builtins.elemAt m 0;
        rest = builtins.elemAt m 1;
      in
      map (
        sp:
        let
          storepath = lib.removePrefix "/nix/store" sp;
          path = "/nix/store${lib.escapeRegex storepath}";
        in
        expandValues "${path}${rest}" value
      ) fileContext.storePaths.${attr};

  genFC =
    fileContext:
    lib.concatStringsSep "\n" (
      lib.flatten (lib.mapAttrsToList (expandRule fileContext) fileContext.rules)
    );

  # Render a module's exported macros (`exports`) as the `.if` that
  # `segenxml.py` turns into policy.xml docs: the module's `<summary>`,
  # `<desc>` and `<required>` header, then every interface/template with its
  # own documentation, `gen_require` block and body.
  # Nix indented strings keep a trailing newline; split them without the
  # resulting empty doc-comment line.
  docSplit =
    value:
    let
      lines = lib.splitString "\n" value;
    in
    if lines != [ ] && lib.last lines == "" then lib.init lines else lines;
  docLines = value: map (line: "## ${line}") (docSplit value);
  indentLine = line: if line == "" then "" else "\t${line}";

  moduleDoc =
    e:
    lib.concatStringsSep "\n" (
      [ "## <summary>" ]
      ++ docLines e.summary
      ++ [ "## </summary>" ]
      ++ lib.optionals (e.desc != null) ([ "## <desc>" ] ++ docLines e.desc ++ [ "## </desc>" ])
      ++ lib.optionals (e.required != null) (
        [
          "## <required val=\"true\">"
        ]
        ++ docLines e.required
        ++ [ "## </required>" ]
      )
    );

  paramDoc =
    param:
    lib.concatStringsSep "\n" (
      [
        "## <param name=\"${param.name}\"${lib.optionalString param.optional " optional=\"true\""}${lib.optionalString param.unused " unused=\"true\""}>"
      ]
      ++ [ "## <summary>" ]
      ++ docLines param.description
      ++ [
        "## </summary>"
        "## </param>"
      ]
    );

  interfaceDoc =
    i:
    lib.concatStringsSep "\n" (
      [ "########################################" ]
      ++ [ "## <summary>" ]
      ++ docLines i.summary
      ++ [ "## </summary>" ]
      ++ lib.optionals (i.desc != null) ([ "## <desc>" ] ++ docLines i.desc ++ [ "## </desc>" ])
      ++ lib.flatten (lib.mapAttrsToList (_: param: paramDoc param) i.params)
      ++ lib.optionals (i.infoflow != null) ([
        "## <infoflow type=\"${i.infoflow.type}\"${
          lib.optionalString (
            i.infoflow.type != "none" && i.infoflow.weight != null
          ) " weight=\"${i.infoflow.weight}\""
        }/>"
      ])
      ++ lib.optionals i.rolecap [ "## <rolecap/>" ]
      ++ lib.optionals i.rolebase [ "## <rolebase/>" ]
      ++ [ "#" ]
    );

  interfaceBody =
    name: i:
    lib.concatStringsSep "\n" (
      [ "${i.type}(`${name}',`" ]
      ++ lib.optionals (i.gen_require != null) (
        [
          "\tgen_require(`"
        ]
        ++ map indentLine (lib.splitString "\n" i.gen_require)
        ++ [ "\t')" ]
      )
      ++ lib.optionals (i.content != "") ([ "" ] ++ map indentLine (lib.splitString "\n" i.content))
      ++ [ "')" ]
    );

  genIf =
    e:
    lib.concatStringsSep "\n\n" (
      [ (moduleDoc e) ]
      ++ map (
        name:
        lib.concatStringsSep "\n" [
          (interfaceDoc e.exports.${name})
          (interfaceBody name e.exports.${name})
        ]
      ) (lib.attrNames e.exports)
    );

  # Materialize a module source to a store path, passing paths through and
  # writing raw declarations to a `writeText` file.
  materializeSource = content: filename: pkgs.writeText filename content;

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
                    path = materializeSource (genIf m.interface + "\n") "${name}.if";
                  }
                ]
              else if isCustom then
                # Custom modules don't have a `.if` in the Reference Policy tree;
                # the build requires one anyway. It must also be *documented*:
                # sedoctool.py only registers a module in modules.conf if its
                # XML carries a module-level `<summary>`, so an empty stub would
                # silently drop the module from the build. When the module itself
                # declares `exports`, `genIf` above renders its header; otherwise
                # provide this documented stub, which the `all_layers` pipeline
                # turns into a registered (loadable) module with no manual
                # modules.conf editing.
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
              if m.fileContext.rules != { } then
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
      ++ lib.optionals hasSenixModules [
        # The `senix` layer that hosts modules which aren't part of the Reference
        # Policy. It must exist (with a metadata.xml) so `make conf` can build
        # policy.xml over it.
        {
          name = "policy/modules/senix/metadata.xml";
          path = pkgs.writeText "senix-metadata.xml" "<summary>SENix custom modules.</summary>";
        }
      ]
    );

  # The policy is built from the Reference Policy sources in full: every built-in
  # module is compiled, and any module declared in `config.security.selinux.modules`
  # is overlaid (taking precedence over the built-in module of the same name).
  policyDrv = pkgs.stdenv.mkDerivation {
    pname = "senix-policy";
    version = "0";

    src = policySrc;

    nativeBuildInputs = [
      pkgs.gnum4
      pythonBindings
      pkgs.getopt
      pkgs.libselinux.bin
      # `chkcon`, used by the Reference Policy's `validate` target to check the
      # appconfig contexts against the linked policy.
      pkgs.libsepol.bin
    ];

    postPatch = ''
      cp -aL ${moduleSourceDrv}/. .
      chmod -R u+w .

      # The rules for the artifact itself (see `targeted/system/init.nix`) use
      # a dummy store path; resolve it to this build's output path.
      for f in $(grep -rl '00000000000000000000000000000000-senix-policy' policy/modules); do
        substituteInPlace "$f" \
          --replace-fail '/nix/store/00000000000000000000000000000000-senix-policy' "$out"
      done

      # Drop every substitution that aliases a path to (or from) `/usr` from the
      # reference policy's `file_contexts.subs_dist`, the merged-usr leftovers
      # (`/bin`, `/lib`, `/lib64`, `/sbin`, `/etc/systemd/*`, `/usr/lib*`, …).
      # NixOS generates the file contexts for its own layout in `modules/files`
      # (`/lib64` and the `/usr` it actually creates), so an aliased lookup
      # hides exactly those rules behind the `/.* → default_t` catch-all —
      # e.g. `/lib64` resolved as `/usr/lib`, which nothing labeled, so
      # `systemd-tmpfiles` created the loader link as `default_t`. libselinux
      # also fails to match a rule whose own path it substituted, so the rules
      # cannot simply be written on both paths.
      subs=config/file_contexts.subs_dist
      awk '$1 !~ /^\/usr/ && $2 !~ /^\/usr/' "$subs" > "$subs.tmp"
      mv "$subs.tmp" "$subs"

      substituteInPlace ./Makefile \
        --replace-fail "/bin/bash" "${lib.getExe pkgs.bash}"
    '';

    configurePhase = ''
      runHook preConfigure

      make conf ''${makeFlags[@]}

      # Bake the declaratively declared booleans into the policy defaults.
      # Without a writable runtime policy store, `setsebool -P` cannot persist
      # them, so the build is the only place they can be applied before the
      # policy is loaded.
      ${lib.concatStringsSep "\n" (
        lib.mapAttrsToList (
          name: value:
          "echo ${lib.escapeShellArg "${name} = ${if value then "true" else "false"}"} >> policy/booleans.conf"
        ) cfg.booleans
      )}

      runHook postConfigure
    '';

    # Compile every module, then link the full policy exactly as `semodule -i`
    # does at runtime (this is the Reference Policy's own `validate` target).
    # The link resolves every `require` against the base and every other
    # module, so an undefined type, a neverallow violation, a duplicate
    # declaration or a conflicting file context fails the *build* instead of
    # the boot. The linked binary policy and the populated policy store are
    # installed as the runtime artifacts; the runtime then only loads them.
    buildPhase = ''
      runHook preBuild

      make ''${makeFlags[@]}

      semanageConf=$NIX_BUILD_TOP/semanage.conf
      storeRoot=$NIX_BUILD_TOP/selinux-store
      mkdir -p "$storeRoot"
      cat > "$semanageConf" <<EOF
      store-root = $storeRoot
      compiler-directory = ${pkgs.policycoreutils}/libexec/selinux/hll
      ${lib.optionalString (cfg.policyVersion != null) "policy-version = ${toString cfg.policyVersion}"}

      [load_policy]
      path = ${lib.getExe' pkgs.policycoreutils "load_policy"}
      [end]

      [setfiles]
      path = ${lib.getExe' pkgs.policycoreutils "setfiles"}
      args = -q -c \$@ \$<
      [end]

      [sefcontext_compile]
      path = ${lib.getExe' pkgs.libselinux.bin "sefcontext_compile"}
      args = -r \$@
      [end]
      EOF

      make validate ''${makeFlags[@]} \
        SEMODULE="${lib.getExe' pkgs.policycoreutils "semodule"} --noreload --config=$semanageConf --store-path=$storeRoot" \
        SETFILES=${lib.getExe' pkgs.policycoreutils "setfiles"} \
        CHKCON=${lib.getExe' pkgs.libsepol.bin "chkcon"} \
        PYTHON=${lib.getExe pythonBindings}

      install -d "$out"/etc/selinux/targeted
      cp -a tmp/policy_root/etc/selinux/targeted/. "$out"/etc/selinux/targeted/

      runHook postBuild
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
      # The policy is installed under the name the runtime loads by
      # (`SELINUXTYPE=targeted`), not the Reference Policy's devel default
      # (`refpolicy`).
      "NAME=targeted"
    ]
    ++ lib.optional (cfg.policyVersion != null) "OUTPUT_POLICY=${toString cfg.policyVersion}"
    ++ lib.optional (cfg.policyVersion != null) "OUTPUT_MODULE=${toString cfg.policyVersion}";

    # Ensure the appconfig for the selected policy type (`seusers`,
    # `default_contexts`, `default_type`, the per-user context files, ...) is
    # complete in the installed tree. libselinux's `get_default_context()`
    # (used by SELinux-aware login programs, e.g. sshd, to place sessions in
    # `sysadm_r:sysadm_t`) reads exactly these files, and without them the
    # context lookup fails under enforcing.
    postInstall = ''
      appconfig=${policySrc}/config/appconfig-mcs
      install -d $out/etc/selinux/targeted/contexts/users
      cp -r $appconfig/. $out/etc/selinux/targeted/contexts/
      # libselinux reads per-SELinux-user context orderings from
      # `contexts/users/<user>`; the appconfig ships those as
      # `<user>_default_contexts` (the REF's Makefile renames them on
      # install).
      for f in $appconfig/*_default_contexts; do
        name=$(basename "$f" _default_contexts)
        [ "$name" = root ] && name=root
        mv $out/etc/selinux/targeted/contexts/$(basename "$f") \
          $out/etc/selinux/targeted/contexts/users/"$name"
      done
      mv $out/etc/selinux/targeted/contexts/seusers $out/etc/selinux/targeted/seusers
    '';
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
        Policy (base module plus every declared module) that is compiled *and
        linked* at build time — the runtime only loads the linked binary — so
        link-time errors fail the build instead of the boot. It replaces the
        pre-built `pkgs.selinux-refpolicy` base.
      '';
    };
  };
}
