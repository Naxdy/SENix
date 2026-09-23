---
name: transcribe-module
description: Transcribe a reference-policy (refpolicy) SELinux module in the SENix repo from store-path catch-all patterns to exact, configuration-scoped store paths — add a `selinuxSupport` option gated on the program's own enable flag, write a hand-maintained module under `nixos/modules/targeted/<layer>/`, list the module in `STRIP_USR` in `scripts/gen-base.py`, and regenerate the base tree. Use when asked to transcribe/target a module (e.g. "transcribe logrotate"), to stop a module labelling every store path matching a `/usr` catch-all, or to make a module's labels depend on whether its program is enabled. For
modules in the `apps` layer, generate them with the `mkSenixAppModule` helper
from `nixos/modules/targeted/apps/default.nix`.
---

# Transcribing a refpolicy module to targeted store paths

SENix generates `nixos/modules/base/<layer>/<module>.nix` from the pinned
Reference Policy with `scripts/gen-base.py`. For every `/usr` rule the generator
substitutes the store regex catch-all `/usr` → `/nix/store/[^/]+`, so e.g.
refpolicy's `/usr/bin/fail2ban` becomes
`/nix/store/[^/]+/bin/fail2ban` — which labels **any** store path whose basename
is `fail2ban`, whether or not the configuration uses it, and which may shadow a
more specific rule from another module.

**Transcription** replaces that catch-all with the exact store path(s) the
running configuration actually provides, and only adds the rules when the
program is enabled. The base module keeps every non-`/usr` rule (and the whole
`.if`/`.te`); the targeted module only adds the store-executable file contexts.
The two definitions merge: `security.selinux.modules.<module>.fileContext.rules`
from base and targeted are combined by the NixOS option system.

Read this with the `avc-triage` skill: transcription is the *label-first*
answer to an AVC — instead of widening a domain, give the right store path the
right type and stop labelling unrelated paths.

## Mental model (where everything lives)

| Path | Role |
| --- | --- |
| `nixos/modules/base/<layer>/<module>.nix` | **Generated** by `scripts/gen-base.py`. Never hand-edit. |
| `nixos/modules/targeted/<layer>/<module>.nix` | Hand-written transcription. Mirrors the refpolicy layer tree. |
| `nixos/modules/targeted/default.nix` | Imports `./<layer>`. |
| `nixos/modules/targeted/apps/default.nix` | **Apps layer factory**: defines `helpers` (`mkSenixAppModule`, `mkServiceProgramModule`) and imports each apps module *as a function* (`(import ./<module>.nix { inherit helpers; })`) — no bare `./<module>.nix` entries. |
| `nixos/modules/targeted/<layer>/default.nix` | Imports each transcribed module (`./<module>.nix`). |
| `nixos/modules/default.nix` | Imports `./targeted` (already wired). |
| `scripts/gen-base.py` | `STRIP_USR` (module names), `IGNORED_MODULES`, `IGNORED_LAYERS`. |

The policy module option tree (`security.selinux.modules.<name>`, defined in
`nixos/default.nix`, consumed by `nixos/build.nix`):

```nix
{
  layer = "services";              # module level! subdir under policy/modules/
  interface = "…";                 # .if   (null = keep refpolicy's)
  typeEnforcement = "…";           # .te   (null = keep refpolicy's)
  fileContext = {
    source = null;                 # a verbatim .fc store path (instead of rules)
    storePaths.<attr> = [ … ];     # store paths referenced by "@attr@" rule keys
    rules = { … };                 # path → "flag gen_context(...)" | [ … ]
  };
}
```

`@attr@` expansion (`expandRule` in `nixos/build.nix`): a rule key matched by
`@([^@]+)@(.*)` is replicated for every path in `storePaths.<attr>`, with the
path's store hash **regex-escaped** and the remainder (`rest`) kept verbatim as
a regex. So `"@fail2ban@/bin/fail2ban"` with `storePaths.fail2ban = [ pkg ]`
becomes `/nix/store/<escaped-hash>-fail2ban-…/bin/fail2ban`. `@attr@` must be at
the **start** of the key and may appear once. `storePaths` values are
`types.pathInStore`; duplicates are removed (`lib.unique`).

`layer` decides which directory the module's overridden sources are written to
(`policy/modules/<layer>/<name>.{te,if,fc}` in `moduleSourceDrv`). `moduleLayer`
in `nixos/build.nix` *does* scan the refpolicy tree, but only to decide whether a
name is a custom module (stub `.if`/`.fc` generation) — the output directory
itself is the **option**, whose default is `"senix"`. So **set it explicitly at
module level** (`security.selinux.modules.<name>.layer`) to the refpolicy layer;
a wrong/default layer puts the overridden `.fc` next to the refpolicy module
instead of over it.

## Procedure

### 1. Identify the module and read its `.fc`

Module names come from the refpolicy tree: `policy/modules/<layer>/<module>.fc`
(and `.te`/`.if`). Find the `/usr`-anchored rules and note the type each path
gets; those are the ones you re-point at store paths.

Materialise the refpolicy source (revision pinned in `nixos/refpolicy.nix`);
an extracted copy usually exists under `/tmp/src/refpolicy-<rev>/`:

```sh
nix build .#checks.x86_64-linux.selinux-enforce.nodes.machine.security.selinux.refpolicy.src
```

### 2. Find the NixOS owner option

The gate lives under the program's own options — usually
`config.services.<name>` or `config.programs.<name>`. Read it and note:

- the enable flag (`cfg.enable`),
- the package option (`cfg.package`; sometimes a sub-attribute or a
  `passthru`, e.g. Chromium's `package.passthru.browser`).

If the refpolicy module has no NixOS counterpart, there is nothing to gate on:
either label `pkgs.<x>` gated on `config.security.selinux.enable` alone, or
leave it to the catch-all (transcription then buys nothing).

### 3. Write `nixos/modules/targeted/<layer>/<module>.nix`

The fail2ban transcription (commit `4c951c9`) is the minimal template:

```nix
{ config, lib, ... }:
let
  inherit (lib) mkOption types;
  cfg = config.services.fail2ban;
in
{
  options.services.fail2ban.selinuxSupport = mkOption {
    type = types.bool;
    default = config.security.selinux.enable;
    defaultText = lib.literalExpression "config.security.selinux.enable";
    description = ''
      Whether to add SELinux modules for this program.
    '';
  };

  config = lib.mkIf (cfg.enable && cfg.selinuxSupport) {
    security.selinux.modules.fail2ban.fileContext = {
      storePaths.fail2ban = [
        cfg.package
      ];
      rules = {
        "@fail2ban@/bin/fail2ban" = "-- gen_context(system_u:object_r:fail2ban_exec_t,s0)";
        "@fail2ban@/bin/fail2ban-client" = "-- gen_context(system_u:object_r:fail2ban_client_exec_t,s0)";
        "@fail2ban@/bin/fail2ban-server" = "-- gen_context(system_u:object_r:fail2ban_exec_t,s0)";
      };
    };
  };
}
```

Notes:

- **`layer`**: fail2ban omits it because the generated base module already sets
  `layer = "services"` and the option value merges. Set it explicitly at
  **module level** whenever the layer is otherwise unset — in particular for
  `apps`-layer modules (bubblewrap, chromium), which have **no** generated base
  module (`IGNORED_LAYERS = { "apps"; }`).
- The option is declared unconditionally; only the `config` is gated.
- One `storePaths` attribute may hold several paths; use several attributes when
  the module spans multiple packages or wrappers (see `dbus.nix`: `dbus` +
  `dbus-broker`; `chromium.nix`: `chromium` + `chromium-wrapper` +
  `google-chrome`).
- Rules that need a specific file type carry the flag in the value: `--` regular
  file, `-d` directory, `-l` symlink, `-c`/`-b`/`-p`/`-s`; no flag = any type. A
  rule with the wrong flag silently does not match — a store *symlink* needs
  `-l`. Multiple flags for one path are a **list**:
  `"@foo@/lib" = [ "-d gen_context(…)" "-l gen_context(…)" ];`.

#### Apps layer: don't write that by hand — use `mkSenixAppModule`

Everything above (the `selinuxSupport` option, the module-level `layer`, the
`storePaths`/`rules` wiring) is already implemented by the `apps` layer's
factory, introduced in commit `f476f36`
(`nixos/modules/targeted/apps/default.nix`). **A module under
`targeted/apps/` is a call to the helper, not a copy of the fail2ban
template.** The file takes the helpers as its argument and is registered in
`apps/default.nix` with that argument applied (see step 4) — the helper is not
a module-system argument, so `{ helpers }:` is required:

```nix
{ helpers }:
helpers.mkSenixAppModule {
  name = "thunderbird";     # nixpkgs option name; also `@thunderbird@` + storePaths key
  category = "programs";    # `programs` or `services`
  rules = {
    "@thunderbird@/bin/thunderbird.*" = "-- gen_context(system_u:object_r:thunderbird_exec_t,s0)";
  };
}
```

Arguments (all documented at the definition in `apps/default.nix`):

- `name` — the `${category}.${name}` gate, plus the `storePaths` key and the
  `@${name}@` rule substitution.
- `category` — `programs` or `services`.
- `moduleName ? null` — SELinux module name when it differs from `name`
  (second `chromium.nix` call: `google-chrome` → module `chromium`).
- `rules` — becomes `fileContext.rules`, verbatim.
- `extraPaths ? { }` — extra `fileContext.storePaths` entries, merged **under**
  the default `{ ${name} = [ cfg.package ]; }` — merge order is
  `extraPaths // { ${name} = [ cfg.package ]; }`, so the default key wins and
  `extraPaths` cannot override `cfg.package`.
- `addPackageOption ? null` — also declare
  `${category}.${name}.package = mkPackageOption pkgs <attr> { }` for programs
  nixpkgs gives no package option (chromium, bubblewrap).
- `addEnableOption ? false` — also declare `${category}.${name}.enable`
  (requires `addPackageOption`); for programs with **no** nixpkgs option at
  all (`programs.bubblewrap`).

What it wires for you:

- `options.${category}.${name}.selinuxSupport`, defaulting to
  `config.security.selinux.enable` — the manual template above, verbatim;
- `security.selinux.modules.<m>.layer = lib.mkDefault "apps"` inside the gated
  config (pitfall 1 already solved — but `mkDefault`, so another definition
  still overrides it);
- the gate: `canEnable && cfg.enable && cfg.selinuxSupport`, where `canEnable`
  requires the **pre-existing** nixpkgs options `${category}.{enable,package}`.
  With neither an nixpkgs `package` option nor `addPackageOption`, the module
  can never fire;
- `environment.systemPackages = [ cfg.package ]` when it added the package
  option and the app is enabled.

`mkServiceProgramModule name` wraps two `mkSenixAppModule` calls
(`programs.<name>` + `services.<name>`) but forwards only `name` and
`category` — `rules`/`addPackageOption` are not passed, and nothing uses it
yet. Read its definition before relying on it; usually write two explicit
calls (as `chromium.nix` does).

### 4. Include it in the module tree

- New layer directory: add `nixos/modules/targeted/<layer>/default.nix` with
  `{ ... }: { imports = [ ./<module>.nix … ]; }`, and add `./<layer>` to the
  `imports` of `nixos/modules/targeted/default.nix`.
- Existing layer: append `./<module>.nix` to that layer's `default.nix`.
- **`apps` layer is special**: `apps/default.nix` binds `helpers` in its `let`,
  so its `imports` entries *apply* it — mirror the neighbours:
  `(import ./<module>.nix { inherit helpers; })`. A bare `./<module>.nix`
  leaves `helpers` unset in the file's argument set and fails evaluation.

Imports are ordinary Nix file names (hyphens allowed); only `.nix` files.

### 5. Add the module to `STRIP_USR`

In `scripts/gen-base.py`:

```python
STRIP_USR = [
    "dbus",
    "fail2ban",
    …
]
```

Membership is matched with `fnmatch` against the module name. For a member,
`parse_fc(..., strip_usr=True)` keeps each upstream `/usr` rule in the
generated file **commented out** (as a reference — see `render_assignment`'s
`commented=True`) instead of rewriting it to `/nix/store/[^/]+`. This is what
removes the catch-all from the base tree; it also gates it on regeneration, so a
later `gen-base.py` run will not restore the regex.

### 6. Regenerate the base modules

```sh
./scripts/gen-base.py               # resolves refpolicy via `nix build`
REFPOLICY_SRC=/tmp/src/refpolicy-… ./scripts/gen-base.py   # reuse an extracted copy
./scripts/gen-base.py --dry-run     # report only
```

Confirm, in the regenerated `nixos/modules/base/<layer>/<module>.nix`, that the
`/usr` rules are now comment lines (like fail2ban's `# "/usr/bin/fail2ban" = …;`)
and that no live `/nix/store/[^/]+/…` rule for them remains. All other rules,
comments and sections must be untouched.

The generator rewrites **every** base file and deletes stale ones, so read
`git diff nixos/modules/base` — it should be exactly the intended change.

### 7. Register new files with git

The flake only sees tracked files; an untracked `targeted/…` file makes
evaluation fail. `gen-base.py` auto-runs `git add -N` for untracked paths Nix
reports (see `register_untracked`); do the same yourself:

```sh
git add -N nixos/modules/targeted/<layer>/…  nixos/modules/targeted/<layer>/default.nix
```

### 8. Verify

1. **Whole tree still evaluates / policy builds:**

   ```sh
   nix build .#checks.x86_64-linux.selinux-enforce -L
   ```

   This does **not** enable the program, so it exercises only the base
   regeneration — but it catches broken Nix in the targeted file's *imports*.

2. **The targeted module itself.** `lib.mkIf false` content is **not validated**
   by the NixOS module system (unknown submodule options are only rejected once
   the branch is active), so a broken transcription evaluates fine until someone
   enables the program. Temporarily enable it in `tests/selinux-enforce/test.nix`
   (or a scratch config) and evaluate the option, then revert:

   ```sh
   nix eval --impure --expr '
   let
     f = builtins.getFlake (toString ./.);
     evalConfig = import (f.inputs.nixpkgs.outPath + "/nixos/lib/eval-config.nix");
     cfg = (evalConfig {
       system = "x86_64-linux";
       modules = [ f.nixosModules.senix {
         security.selinux.enable = true;
         services.<name>.enable = true;      # e.g. programs.bubblewrap.enable
       } ];
     }).config;
     m = cfg.security.selinux.modules.<module>;
   in { layer = m.layer; storePaths = builtins.attrNames m.fileContext.storePaths; rules = m.fileContext.rules; }'
   ```

   Assert `layer` is the refpolicy layer (not `"senix"`) and the rules are the
   expected `@attr@` bindings. Optionally also enable the program in the real VM
   test and confirm the path carries the expected context
   (`getfattr -n security.selinux --only-values <store-path>/bin/x`) — this is
   the real end-to-end proof, but it is slow.

3. **No catch-all left** for the module: search the regenerated base file for
   `nix/store/[^/]+`; only commented-out reference lines (`# "/usr/…"`) should
   remain.

4. Run the repo formatter before committing: `nix fmt` (treefmt: `nixfmt`, plus
   `typos` — the skill and any `.md` you touch are spell-checked).

## Edge cases and pitfalls (learned from the hand-written modules)

1. **`layer` belongs at module level.** Putting it inside `fileContext` is an
   eval error (`security.selinux.modules.<m>.fileContext.layer does not exist`)
   that is *invisible* while the program is disabled. Both `bubblewrap.nix` and
   `chromium.nix` had this bug. `layer` must sit next to `fileContext`:
   `security.selinux.modules.<m> = { layer = "apps"; fileContext = { … }; };`.

2. **Shallow attrset merge silently drops siblings.** Building the option with
   `(listToAttrs …) // { chromium.package = …; }` *replaces* `chromium`
   wholesale, discarding `chromium.selinuxSupport`; enabling Chromium then
   errored with `attribute 'selinuxSupport' missing`. Merge per-name with
   `lib.optionalAttrs` (or `lib.recursiveUpdate`).

3. **A module still has a `.te`/`.if`.** Transcription only converts the
   `/usr`/store file contexts. Do **not** re-declare `typeEnforcement` or
   `interface` in the targeted file unless you intend to replace the refpolicy
   ones wholesale (`moduleSourceDrv` overlays them). Extra grants for a
   refpolicy-owned domain go in a companion `*_extra` module instead (see
   `nscd.nix` / `avc-triage`).

4. **Conflicting contexts.** Two modules assigning different types to the same
   store path is a conflict `semodule` rejects. Keep each path owned by exactly
   one module. When a broad catch-all module would otherwise also claim the
   path, carve it out with the `security.selinux.exclusions.*` options rather
   than fighting regex precedence:

   - `exclusions.systemdUnits` — `init.nix` labels all systemd units
     `systemd_unit_t`; `restorecond.nix` excludes its unit to give it
     `restorecond_unit_t`.
   - `exclusions.etc` — `files.nix` labels all of `config.environment.etc`;
     `selinuxutil.nix` excludes `selinux/config`.
   - `exclusions.systemdPackages` — `systemd.nix` labels systemd unit-providing
     packages.

5. **Prefer the config's package over `pkgs.<x>`.** Use `cfg.package` (or
   `cfg.dbusPackage`/`brokerPackage`, `package.passthru.browser`, …) so the
   labels follow overrides. Never hard-code `pkgs.<x>` when an option exists.

6. **Multiple paths can produce conflicting rules within one module** if two
   entries in `storePaths` are the same derivation (deduped by `lib.unique`) or
   if a path also appears in the refpolicy's kept rules — check the generated
   `.fc` (module source farm) and the VM label when unsure.

7. **`STRIP_USR` is per module name, not per layer.** It strips only rules
   anchored at `/usr`; non-`/usr` rules (`/etc`, `/var`, `/run`, `HOME_DIR`, …)
   stay live in the base module. That is intended: only the store paths need
   transcription.

8. **`apps`-layer modules have no base module** (`IGNORED_LAYERS`), so the
   targeted file is the *only* source of their `.fc` — it must set `layer`
   explicitly and provide the full rule set. `mkSenixAppModule` does both
   (`layer = lib.mkDefault "apps"`, `inherit rules`); hand-written files must
   keep doing it themselves.

9. **Do not hand-edit generated files.** `gen-base.py` overwrites every
   `nixos/modules/base/**` file and deletes stale ones; any manual change is
   lost on the next run. If the rule is store- or NixOS-specific, it belongs in
   the targeted (or another hand-written) module.

10. **`@attr@` requires the matching `storePaths` entry.** A rule referencing
    `@foo@` with no `storePaths.foo` fails evaluation; extra `storePaths` entries
    with no referencing rule are harmless but pointless.

11. **Directory names vs module names.** A new refpolicy layer gets its own
    `nixos/modules/targeted/<layer>/default.nix` and an entry in
    `targeted/default.nix`; a new *module* only needs a line in its layer's
    `default.nix`.

## Reference

- `nixos/build.nix` — `expandRule`/`genFC` (`@attr@` expansion, regex escaping),
  `moduleSourceDrv` (where `layer` routes sources), `moduleLayer` (refpolicy
  auto-detection).
- `nixos/default.nix` — the `security.selinux.modules` option definitions and
  `exclusions`.
- Generated base example with stripped rules:
  `nixos/modules/base/services/fail2ban.nix` (see the three commented
  `/usr/bin/fail2ban*` lines).
- Apps-layer helper API + registration:
  `targeted/apps/default.nix` (`mkSenixAppModule` argument docs, `helpers`
  wiring); exemplars `thunderbird.nix` (minimal helper call),
  `bubblewrap.nix` (`addPackageOption` + `addEnableOption` for a program
  nixpkgs doesn't provide), `chromium.nix` (two calls into one SELinux module
  via `moduleName`, plus `extraPaths` for wrapper/unwrapped packages).
- Hand-written exemplars: `targeted/services/fail2ban.nix` (minimal),
  `dbus.nix` (multi-package), `systemd.nix`/`init.nix`/`logging.nix`/`selinuxutil.nix`
  (store-path transcription of modules that also keep live `/etc`/`/run`/`/var`
  rules), `nscd.nix` (transcription + `*_extra` grants).
- `tests/selinux-enforce/test.nix` — the VM test; `tests/screen` for authoring a
  full custom module.
