---
name: avc-triage
description: Iteratively diagnose and fix SELinux AVC denials in the SENix repo (NixOS + reference policy) — boot the selinux-enforce VM in enforcing mode, collect exactly one run's denials, prefer relabelling files over new grants, use reference-policy interface macros and Fedora's selinux-policy as reference, keep grants minimal, and never widen default_t or unlabeled_t.
---

# AVC triage in SENix

Fixing `avc: denied` records that a NixOS boot produces under SELinux. SENix is a
NixOS module tree that builds a MCS reference policy (`security.selinux.*`) and
labels the store through the `metafs` FUSE overlay. Denials come from two
places: **a file with the wrong label** (label bug) or **a domain lacking a
permission** (policy gap). Prefer the former.

## Non-negotiable rules

1. **Run enforcing.** Fixing happens against `mode = "enforcing"`. A permissive
   boot reports every operation the policy *would* deny (`permissive=1`) and then
   keeps going down the same path, so the log is a superset: noise, plus
   secondary denials the real system would never reach because the primary
   failure would already have stopped it. An enforcing boot reports only the
   denials that actually fail (`permissive=0`) and halts the failing path at the
   point of denial, giving a small, causally-ordered set. `tests/selinux-enforce/test.nix`
   already sets `mode = "enforcing"` — keep it that way.
2. **One run, one batch.** Fix *every* denial from a single VM run, rebuild,
   and only then look at the next run. Never mix AVCs from different runs into
   one batch. Every label or grant change shifts what the boot reaches next and
   therefore what it denies; denials from an older run are often already moot,
   and acting on them buys unnecessary grants. A batch fix also means one build
   cycle per iteration instead of one per denial.
3. **Label first.** If a denial can be resolved by giving the offending path its
   correct type, that is the preferred fix — SELinux is a labelling system, and
   the refpolicy/Fedora answer to "domain X cannot touch path P" is almost always
   a `.fc` rule, not a widened allow. Consult the pinned reference policy and
   Fedora's `selinux-policy` for how they label the same kind of path.
4. **Minimum grants.** If no correct label exists and a grant is genuinely
   required, add the *absolute minimum* set of permissions for the *specific*
   source and target types and class — never `*`, never an attribute the
   offender happens to be in (e.g. `non_security_file_type`) if a precise target
   exists. Do not pre-emptively fix the "next" denial you can predict.
5. **Interfaces over hand-written `allow`.** Reach for an existing
   reference-policy interface macro before writing a raw statement:
   `files_read_usr_symlinks()`, `files_read_etc_symlinks()`,
   `files_watch_etc_files()`, `miscfiles_read_localization()`, `kernel_use_fds()`,
   `fs_getattr_nsfs()`, `selinux_set_all_booleans()`, … These encapsulate the
   full, correct permission set and keep us aligned with upstream. Grep the
   refpolicy `.if` files for the operation; only fall back to `allow` when no
   interface covers it. `nixos/modules/senix-init.nix`, `senix-logging.nix` and
   `nscd.nix` show the style.
6. **`default_t` and `unlabeled_t` are NEVER given permissions.** No exceptions,
   no matter what the denial looks like. An agent that concludes otherwise is
   wrong about how SELinux works: `default_t` is the reference policy's catch-all
   for paths with no `.fc` rule (`files.fc` has `/.* → default_t`) and
   `unlabeled_t` is what an object carries when it has no label at all. Granting
   either one is granting "everything, everywhere" and hides the actual bug — the
   missing label. If you see a denial with one of these as `tcontext`, the fix is
   a `.fc` rule (or moving the label assignment earlier), full stop. (The
   pre-existing `unlabeled_t ... associate` in `senix_store` is the metafs
   labelling carve-out, not precedent — never copy it.)

## Loop

```sh
nix build .#checks.x86_64-linux.selinux-enforce -L --no-link > /tmp/run.log 2>&1
```

Takes ~1–2 min and is occasionally flaky ("session ended with error", a
pre-existing EPERM/panic flake) — just rerun. Inspect `git diff` afterwards; an
untracked new module file is invisible to the flake until registered with
`git add -N` (`nixos/modules/default.nix`/`nixos/build.nix` must see it).

Collect the run's real denials (enforcing run ⇒ `permissive=0`):

```sh
sed -nE 's/.*denied  \{ ([a-z_ ]+) \} for.*comm="([^"]*)".*scontext=system_u:[^:]+:([a-z_]+):s0 tcontext=system_u:[^:]+:([a-z_]+):s0 tclass=([a-z_]+).*/\1 | \2 | \3 -> \4 | \5/p' /tmp/run.log | sort | uniq -c | sort -rn
```

Read the raw lines with the `grep` tool on `/tmp/run.log` (pattern
`avc:  denied`) — the console is **rate-limited** (`kauditd_printk_skb: N
callbacks suppressed`), so if you need every record, temporarily add to the
node config:

```nix
boot.kernel.sysctl."kernel.printk_ratelimit" = 0;
```

and revert before committing. Also read what the tools themselves printed —
their errors name the exact path and are often more informative than the audit
record: search the log for `Permission denied`, `Failed to`, `systemd-tmpfiles[`.

Then triage the batch, rebuild, and rerun. Expect each fix to **expose the next**
denial (tmpfiles creating a directory, then the symlink in it, then reading the
symlink, …) — that is the loop working, not a regression.

## Reading a denial

```
denied { read } for pid=… comm="X" path="/systemd/journal/stdout"
  scontext=system_u:system_r:syslogd_t:s0        <- who (source)
  tcontext=system_u:object_r:kernel_t:s0         <- what (target)
  tclass=unix_stream_socket permissive=0
```

- `name=` instead of `path=` means only a dentry: find the real path with
  `find /nix/store -maxdepth 8 -name <name>` (store paths are deep; the maxdepth
  matters) and confirm the label with
  `getfattr -h -n security.selinux --only-values <path>` (`-h` = the symlink
  itself, omit it for the target).
- Compare against what the policy *expects*: `matchpathcon -n <path>`.
- Available in the VM (`pkgs.setools`, `pkgs.policycoreutils`): `sesearch -A -s
  <src> -t <tgt> -c <class>`, `sesearch -T`, `seinfo -a<type>`,
  `seinfo -x -t <type>`, `getsebool`, `semanage boolean -l`, `sestatus`.
- **Pre-policy records are noise.** Denials from the initrd (before
  `load_policy`) run with `permissive=1`; do not fix those. `tctx=kernel_t` on a
  socket is usually a pre-policy artefact: a socket's label defaults to the
  creating task's type, so sockets PID 1 opened before the policy are `kernel_t`
  and get handed to services across switch-root.

## Fixing a label (preferred)

File contexts live per module in `config.security.selinux.modules.<name>.fileContext.rules`
(`path → "rule"`, or a list of rules when several file-type flags apply). The
path is matched against the *system* path tree; store content is matched with
`/nix/store/[^/]+/…` or an `@attr@` placeholder expanded from
`fileContext.storePaths.<attr>`.

```nix
fileContext = {
  storePaths.foo = [ pkgs.foo ];
  rules = {
    "@foo@/bin/foo"  = "-- gen_context(system_u:object_r:foo_exec_t,s0)";
    "@foo@/lib"      = [ "-d gen_context(…:foo_lib_t,s0)" "-l gen_context(…:foo_lib_t,s0)" ];
    "/nix/var(/.*)?" = "gen_context(system_u:object_r:var_lib_t,s0)";
  };
};
```

File-type flags (refpolicy `.fc` syntax): `--` regular file, `-d` directory,
`-l` symlink, `-c` char device, `-b` block device, `-s` socket, `-p` fifo; no
flag = all types. A rule missing the right flag silently doesn't match — a store
*symlink* (e.g. `bin/fsck.ext4`) stays `usr_t` if the only rule is `--`.
A **specific** rule beats the catch-all rules (`/.* → default_t`,
`/nix/store/[^/]+(/.*)? → usr_t`) regardless of order.

Where to put it:

- The generated tree `nixos/modules/base/<layer>/<module>.nix` (see
  `scripts/gen-base.py`) is the refpolicy translation. Its `.fc` is adapted to
  the store by `gen-base.py` (rewrites `/usr` → `/nix/store/[^/]+`, drops
  non-NixOS top-level dirs, resolves `distro_nixos`/`init_systemd` conditionals).
  **Do not hand-edit it** for a one-off rule — regenerate it or add the rule to
  the hand-written module instead, or your change is lost on the next
  `gen-base.py` run.
- Store-specific and NixOS-only rules go in the hand-written module that owns
  the paths: `nixos/modules/files.nix` (the generic `/nix`, `/etc`, `/lib64`,
  profile pointers), `logging.nix`, `systemd.nix`, `dbus.nix`, `nscd.nix`,
  `selinuxutil.nix`, `senix-*.nix`. A declared module's `fileContext.rules`
  **merge** with the same module's generated rules (both define the option), so
  you can add individual rules without copying the whole `.fc`.
- A brand-new owner becomes a new `nixos/modules/<name>.nix` added to the
  `imports` list of `nixos/modules/default.nix`.

Runtime paths that no `setfiles` run reaches (initrd-created, tmpfs, cgroupfs)
are the domain of the initrd `selinux-init` relabel block in `nixos/default.nix`
(`relabel-extra.d` list, `setfiles` calls, cgroup seeding). Two hard-won facts:

- `setfiles`/`restorecon`/systemd's `label_fix()` **skip a label that is already
  equal**, so an fs whose file contexts equal the kernel-computed context
  (cgroup2's `genfscon cgroup_t`) never gets an xattr at all — and the kernel
  only derives a child node's label from a parent that has one. That's why the
  cgroup tree is seeded with *unconditional* `setfattr` writes
  (`find /sys/fs/cgroup | matchpathcon -n | setfattr`).
- A path excluded from relabeling (e.g. `/run/.*` `<<none>>`) keeps whatever the
  creating filesystem would give it; add a specific `.fc` rule to override.

## Fixing a grant (when no correct label exists)

Refpolicy convention is that a grant belongs in the module that owns the source
domain (`X.te`). SENix honours that for labels, but **declaring
`typeEnforcement` on a module that exists in the reference policy replaces its
`.te` wholesale** (and `interface` replaces its `.if`) — see `moduleSourceDrv` in
`nixos/build.nix`. So the working patterns here are:

- **Call an existing interface** from a custom section of the tree. If the
  grant already exists as an interface in the target's module (the refpolicy
  tree is full of them), the caller is what you write.
- **Add the grant to a `_extra`/`senix_*` module.** Extra grants for a
  refpolicy-owned domain go into a custom companion module: `nscd_extra`
  (`nixos/modules/nscd.nix`) adds to `nscd_t`; `senix_init`,
  `senix_logging` hold the boot/journald/systemd-specific additions. These are
  not in the reference tree, so they are registered automatically and can safely
  carry `gen_require(...)` + interfaces + bare `allow`s. `layer` names the
  reference layer that owns the domain (`services` for `nscd_extra`,
  `system` for the senix boot modules, `kernel` for `senix_store`).
- A custom module needs no `.te`/`.if` when it only adds file contexts; when it
  *does* provide an `.if`, the body must start with a `<summary>` doc comment or
  `sedoctool.py` silently drops the module from `modules.conf`. (A missing `.if`
  is auto-stubbed with a summary by the build.)

For each candidate grant, before writing it:

1. Search the reference policy for an interface that grants what you need and
   the caller's relationships — grep the `.if` files of the *owning* module
   first, then the target's.
2. Check whether the permission is behind a **tunable/boolean** that is simply
   off. Several rounds of "missing" permissions are refpolicy tunables at their
   restrictive default (`gen_tunable(..., false)` + `tunable_policy()`), e.g.
   `systemd_tmpfiles_manage_all`. `sesearch -A -s <src> -t <tgt> -c <class>`
   prints conditional rules as `[ boolean ]:True|False`. Enable with
   `config.security.selinux.booleans.<name> = lib.mkDefault true;` in the owning
   module (see `nixos/modules/systemd.nix`) rather than duplicating the rules.
3. If refpolicy lacks the grant, check Fedora's `selinux-policy` (it is usually
   ahead on systemd/NixOS-adjacent integration) and port its shape — but still
   minimal: the same source, target and class, not Fedora's whole allow line if
   it is broader than the denied permission.

## Reference sources

- Pinned reference policy: materialise with
  `nix build .#checks.x86_64-linux.selinux-enforce.nodes.machine.security.selinux.refpolicy.src`
  (the revision is pinned in `nixos/refpolicy.nix`). An extracted copy often
  already exists under `/tmp/src/refpolicy-<rev>/`; `policy/modules/<layer>/<module>.{te,if,fc}`
  is the authority for labels, interfaces and grants. `support/sedoctool.py`
  and `support/segenxml.py` explain module registration.
- Fedora: `https://github.com/fedora-selinux/selinux-policy` (a checkout may be
  at `/tmp/src/selinux-policy-rawhide`). Fedora splits differently (has
  `contrib`, no `session` layer) and adds distro-specific rules; use it for
  guidance on *how* a denial is handled elsewhere, then express it in the owning
  SENix module.
- The reference policy's own README/docs describe `.fc` matching order, the
  file-type flags and the `gen_context`/interface conventions.

## Verify and commit

Rerun the test after each batch and assert:

- the target denials are gone: grep the fresh `/tmp/run.log` for the
  `scontext`/`tclass` pairs you fixed;
- the test still passes: the script reports success and the build exits 0;
- the test's own `enforce-learn` assertion still holds (confined domain reads its
  data, cannot read `secret` — that denial is the point of the test, never
  "fix" it away).

Commit policy fixes separately from test scaffolding, with the message the user
asks for (this repo's convention is `AVCs: fix`, no body). Revert every
temporary diagnostic (`kernel.printk_ratelimit`, in-VM diag blocks) before
committing, and do not commit VM-test workarounds as policy.
