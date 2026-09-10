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
      stubIf = pkgs.writeText "stub.if" "";
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
                # the build requires one, so provide an empty file.
                [
                  {
                    inherit dir;
                    name = "${dir}/${name}.if";
                    path = stubIf;
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

  # Custom modules (not part of the Reference Policy) — detected by scanning the
  # source, not by their declared `layer` (which may point into the Reference
  # Policy, e.g. `kernel`, to make a custom module a base module). These aren't
  # in the refpolicy's generated `modules.conf`, so we append them; built-in
  # Reference Policy modules are left as-is (we build all of them). Custom
  # modules placed in the `kernel` layer are appended as `base` so their
  # statements (e.g. `sid init`) are compiled into the base policy.
  customInfo = lib.concatStringsSep " " (
    map (name: "${name}=${if mods.${name}.layer == "kernel" then "base" else "module"}") (
      lib.filter (name: moduleLayer name == "senix") moduleNames
    )
  );

  # Common make flags for the Reference Policy build (single line so they can
  # be interpolated directly into a `make` invocation).
  refpolicyTools = "CHECKPOLICY=${pkgs.checkpolicy}/bin/checkpolicy CHECKMODULE=${pkgs.checkpolicy}/bin/checkmodule SEMODULE=${pkgs.policycoreutils}/bin/semodule SEMOD_PKG=${pkgs.semodule-utils}/bin/semodule_package SEMOD_LNK=${pkgs.semodule-utils}/bin/semodule_link SEMOD_EXP=${pkgs.semodule-utils}/bin/semodule_expand DISTRO=nixos SYSTEMD=y UBAC=y";

  # The policy is built from the Reference Policy sources in full: every built-in
  # module is compiled, and any module declared in `config.security.selinux.modules`
  # is overlaid (taking precedence over the built-in module of the same name).
  policyDrv = pkgs.stdenv.mkDerivation {
    pname = "selinux-policy";
    version = "1";
    dontUnpack = true;

    nativeBuildInputs = [
      pkgs.gnumake
      pkgs.gnum4
      pkgs.checkpolicy
      pkgs.policycoreutils
      pkgs.semodule-utils
      pkgs.gawk
      pkgs.gnused
      pkgs.python3
      pkgs.gnugrep
      pkgs.getopt
      pkgs.findutils
    ];
    buildPhase = ''
      runHook preBuild

      set -euo pipefail

      # Build in a writable copy of the Reference Policy sources.
      cp -a ${policySrc}/. "$PWD/refpolicy"
      chmod -R u+w "$PWD/refpolicy"
      cd refpolicy

      # Generate build.conf / modules.conf and any `.te`/`.if`/`.fc` from
      # `.in`/`.m4` sources (e.g. `kernel/corenetwork`).
      make conf \
        ${refpolicyTools}

      # Append custom (senix) modules to modules.conf; every built-in module
      python3 - policy/modules.conf ${customInfo} <<'SENIX_PYEOF'
      import sys

      conf = sys.argv[1]
      entries = [e.split("=", 1) for e in sys.argv[2:] if "=" in e]
      existing = set()
      out = []
      with open(conf) as f:
          for line in f:
              s = line.strip()
              parts = s.split()
              if len(parts) == 3 and parts[1] == "=":
                  existing.add(parts[0])
              out.append(line)
      for name, status in entries:
          if name not in existing:
              out.append(f"{name} = {status}\n")
      with open(conf, "w") as f:
          f.writelines(out)
      SENIX_PYEOF

      # The `init` module only declares `init_t`/`init_exec_t`/`initrc_transition_domain`
      # once; we move those into the `init_context` base module (which declares
      # `sid init init_t`, only valid in the base). Strip them from `init.te`
      # so the base is the single source of truth and checkmodule doesn't see a
      sed -i \
        -e 's|^\(\tclass passwd rootok;\)$|\1\n\ttype init_t;\n\ttype init_exec_t;|' \
        -e '/^attribute initrc_transition_domain;/d' \
        -e '/^type init_t, initrc_transition_domain;/d' \
        -e '/^type init_exec_t;/d' \
        policy/modules/system/init.te
      cp -a ${moduleSourceDrv}/. .

      # `cp -a` preserves the (read-only) source modes; ensure everything is
      # writable again before any in-place `sed`/`make` runs.
      chmod -R u+w .

      # The `init_context` base module (declared via `security.selinux.modules`)
      # sets `sid init init_t` so PID 1 boots as `init_t`; drop the Reference
      # Policy's own `sid init` (which is `unlabeled_t`) so there is exactly one
      # `sid init` statement.
      sed -i '/^sid init[[:space:]]/d' policy/modules/kernel/kernel.te

      export INSTALL=${pkgs.coreutils}/bin/install

      mkdir -p tmp

      make all install install-headers ${refpolicyTools} prefix=$out DESTDIR=$out


      # The Reference Policy's `install` also stages modules under
      # `$(prefix)/usr`, doubling everything (deduped but confusing); drop it.
      rm -rf "$out/usr"

      runHook postBuild
    '';
    # `buildPhase` runs `make install` with `prefix=$out DESTDIR=$out`; the
    # default stdenv `installPhase` would run `make install` again without those
    # (installing to `/usr`), so make it a no-op.
    installPhase = "true";
  };

  # Every store path referenced by any module's fileContext.storePaths.
  storePaths = lib.concatLists (
    lib.mapAttrsToList (
      _: m: lib.concatLists (lib.mapAttrsToList (_: paths: paths) m.fileContext.storePaths)
    ) mods
  );
  storePathsUnique = lib.unique storePaths;

  # Raw file contexts (with `gen_context(...)` still unexpanded) across all modules.
  squashfsFC = lib.concatStringsSep "\n" (
    lib.filter (s: s != "") (
      map (m: if m.fileContext.rules != { } then genFC m.fileContext else "") (lib.attrValues mods)
    )
  );
  # Because `squashfsFC` is huge once every module contributes nixified rules,
  # write it to a store file so the build phase never has to carry it inline
  # (which overflows ARG_MAX).
  squashfsFCDrv = pkgs.writeText "file_contexts" squashfsFC;
  # Mirror a store path's tree into the staging area as empty files / symlinks /
  # directories, so the SquashFS carries only metadata (never file contents).
  mirrorStorePath = sp: ''
    src=${toString sp}
    dst="$staging/nix/store/$(basename "$src")"
    mkdir -p "$dst"
    (cd "$src" && find . -mindepth 1 | while IFS= read -r p; do
      if [ -d "$p" ] && [ ! -L "$p" ]; then
        mkdir -p "$dst/$p"
      elif [ -L "$p" ]; then
        ln -s "$(readlink "$p")" "$dst/$p"
      else
        touch "$dst/$p"
      fi
    done)
  '';

  mirrorStorePaths = lib.concatStrings (map mirrorStorePath storePathsUnique);
  # Python helper: match staged store files against the expanded file contexts and
  # emit `mksquashfs` pseudo `x` definitions. Writing the `security.selinux` xattr
  # this way bakes it into the image without needing an active SELinux LSM on the
  # build host (so a no-SELinux -> SELinux switch needs only a single rebuild).
  pseudoGen = ''
    import re, os, sys

    def main(fc, store):
        entries = []
        with open(fc) as f:
            for line in f:
                line = line.rstrip('\n')
                if not line or line.startswith('#'):
                    continue
                parts = line.split('\t')
                if len(parts) < 2:
                    continue
                try:
                    entries.append((re.compile(parts[0].strip()), parts[-1].strip()))
                except re.error:
                    pass
        out = []
        for root, dirs, files in os.walk(store):
            for name in dirs + files:
                full = os.path.join(root, name)
                rel = os.path.relpath(full, store)
                logical = '/nix/store/' + rel
                ctx = None
                for regex, c in entries:
                    if regex.search(logical):
                        ctx = c
                if ctx:
                    out.append('%s x security.selinux=%s' % (rel.replace('\\', '\\\\'), ctx))
        sys.stdout.write('\n'.join(out))

    main(sys.argv[1], sys.argv[2])
  '';

  squashfsDrv = pkgs.stdenv.mkDerivation {
    pname = "selinux-store-metadata";
    version = "1";
    dontUnpack = true;
    nativeBuildInputs = [
      pkgs.squashfsTools
      pkgs.python3
      pkgs.gnum4
      pkgs.gawk
      pkgs.findutils
    ];

    buildInputs = [
      cfg.refpolicy.package
    ]
    ++ storePathsUnique;

    buildPhase = ''
            runHook preBuild

            set -euo pipefail

            m4support=$(find ${supportDir} -maxdepth 1 -name '*.spt' | sort)
            mls_sens=$(awk -F'[ :=]+' '/^MLS_SENS/ {print $NF}' ${cfg.refpolicy.package.src}/build.conf)
            mls_cats=$(awk -F'[ :=]+' '/^MLS_CATS/ {print $NF}' ${cfg.refpolicy.package.src}/build.conf)
            mcs_cats=$(awk -F'[ :=]+' '/^MCS_CATS/ {print $NF}' ${cfg.refpolicy.package.src}/build.conf)
            M4PARAM="-D mls_num_sens=$mls_sens -D mls_num_cats=$mls_cats -D mcs_num_cats=$mcs_cats"

            staging=$(mktemp -d)

            # Materialize the raw file contexts, then expand the `gen_context`
            # macros (the `divert.m4`/`undivert.m4` support files activate the
            # macro definitions that the `.spt` support files divert).
            cp ${squashfsFCDrv} "$staging/file_contexts"
            m4 $M4PARAM -s ${policySrc}/support/divert.m4 $m4support ${policySrc}/support/undivert.m4 "$staging/file_contexts" > "$staging/file_contexts.x"

            ${mirrorStorePaths}

            # Write the matcher and generate per-file `security.selinux` xattr
            # definitions as a `mksquashfs` pseudo file. This bakes the labels
            # into the image unconditionally, so the build works on hosts without
            # an active SELinux LSM (no-SELinux -> SELinux needs one rebuild).
            cat > "$staging/matcher.py" <<'SENIX_PYEOF'
      ${pseudoGen}
      SENIX_PYEOF
            python3 "$staging/matcher.py" \
              "$staging/file_contexts.x" "$staging/nix/store" > "$staging/pseudo"

            mksquashfs "$staging/nix/store" "$out" \
              -pf "$staging/pseudo" -noappend -xattrs -no-progress > /dev/null
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
      default = policyDrv;
      description = ''
        The final, combined SELinux policy package built entirely from
        `config.security.selinux.modules`. It is a self-contained Reference
        Policy (base module plus every declared module) that is loaded at boot
        and activation, replacing the pre-built `pkgs.selinux-refpolicy` base.
      '';
    };
  };

  config = {
    security.selinux.build.squashfs = squashfsDrv;
  };
}
