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
                parts = line.split('\t', 1)
                if len(parts) != 2:
                    continue
                try:
                    entries.append((re.compile(parts[0].strip()), parts[1].strip()))
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
                    out.append('%s x security.selinux=%s' % (rel, ctx))
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
      refpolicy
    ]
    ++ storePathsUnique;

    buildPhase = ''
            runHook preBuild

            set -euo pipefail

            include=${includeDir}
            m4support=$(find "$include/support" -maxdepth 1 -name '*.spt' | sort)
            mls_sens=$(awk -F'[ :=]+' '/MLS_SENS/ {print $NF}' "$include/build.conf")
            mls_cats=$(awk -F'[ :=]+' '/MLS_CATS/ {print $NF}' "$include/build.conf")
            mcs_cats=$(awk -F'[ :=]+' '/MCS_CATS/ {print $NF}' "$include/build.conf")
            M4PARAM="-D mls_num_sens=$mls_sens -D mls_num_cats=$mls_cats -D mcs_num_cats=$mcs_cats"

            staging=$(mktemp -d)

            # Materialize the raw file contexts, then expand the `gen_context` macros.
            cat > "$staging/file_contexts" <<'SENIX_FCEOF'
      ${squashfsFC}
      SENIX_FCEOF
            m4 $M4PARAM $m4support "$staging/file_contexts" > "$staging/file_contexts.x"

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

  config = {
    security.selinux.build.squashfs = squashfsDrv;
  };
}
