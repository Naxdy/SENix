# SENix

**S**ecurity **E**nhanced **Nix** — brings SELinux to NixOS as a declarative, NixOS-module-driven system. Design decisions are human-owned; agentic changes must not break the core invariant below. System is verified end-to-end as NixOS VMs in `tests/`.

> Core invariant: the real `/nix/store` must **never** carry xattrs. All SELinux labels live in the in-memory xattr map of a bespoke FUSE filesystem, `metafs`, which is mounted over the store.

## Repo layout

- `nixos/` — the NixOS module implementing `security.selinux.*` (options, policy build, initrd + activation integration).
- `nixos/build.nix` — builds the combined SELinux policy (refpolicy base + every declared module) into `.pp` packages.
- `nixos/modules/` — per-component policy module definitions (files, systemd, init, corecommands, libraries, dbus, nscd, selinuxutil, chromium, bubblewrap, senix-store, senix-init).
- `metafs/` — Rust FUSE daemon serving the read-only store overlay (`src/main.rs`, `src/fs.rs`, `src/xattrs.rs`).
- `tests/` — NixOS VM tests: `selinux-enforce`, `selinux-switch`, `metafs`, `screen`.

## Boot flow

### Initrd (`boot.initrd.systemd.services`, order enforced by unit deps)

1. `selinux-metafs` mounts the metafs overlay at `/sysroot/nix/store` (source == mountpoint) before any relabeling, with `--seclabel` and `fscontext=system_u:object_r:senix_meta_t:s0`. The daemon is built to survive switch-root (see metafs).
2. `selinux-init` (oneshot, `before=initrd-fs.target`):
   - loads policy modules with `semodule -s <type>` (policy store rooted at `/run/selinux` via a generated `semanage.conf`; `/etc/selinux/<type>` is symlinked to it so libselinux tools find policy + file_contexts — the initrd `/var` is read-only);
   - registers `/run/systemd/relabel-extra.d/10-senix.relabel` listing `/nix`, `/nix/store`, `/etc`, `/var`, `/home`, `/usr` for systemd to relabel post-initrd;
   - runs `load_policy -i` and `setsebool -P`;
   - relabels the **initrd's** `/nix/store` (`setfiles -F`), then the **host's systemd** store path only (`setfiles -r /sysroot … ${systemd.package}` — systemd's label is the ground truth for the `init_t` handoff), then the rest of `/sysroot` excluding `/sysroot/nix/store`.

### Post-initrd handoff (host systemd)

1. systemd (built `withSelinux`) completes SELinux setup and, in `mount_setup()`, relabels the predefined trees `/dev`, `/dev/shm`, `/run` plus every absolute path listed in `/run/systemd/relabel-extra.d/*.relabel` (embedded systemd feature — `relabel_extra()` in `src/shared/mount-setup.c`): each path is relabeled recursively, then the drop-in files and directory are deleted.
2. `selinux-metafs-remount` bind-remounts `/nix/store` read-only (`mount --bind /nix/store /nix/store; mount -o remount,ro,bind`, ordered before `nix-daemon`). The store is then ro for every process except the Nix daemon, which needs rw — metafs deliberately does not force ro itself (see metafs), so the daemon can remount rw within its own mount namespace.
3. Normal boot proceeds under the SELinux policy.

## metafs (the store overlay)

- A read-only passthrough FUSE filesystem over the real store (source may be the same path as the mountpoint).
- Content I/O is served via **FUSE passthrough**: the daemon registers an open backing fd with the kernel (`FUSE_PASSTHROUGH` capability; `set_max_stack_depth(2)`, since passthrough only activates when the connection's stack depth > 0) and the kernel serves reads/writes straight from that fd — no round-trip through the daemon. Structural ops (create, unlink, rename, mkdir, setattr, symlink) pass through to the backing FS exactly.
- Xattrs are the one exception: `{set,get,list,remove}xattr` are answered from an in-memory `DashMap<u64, BTreeMap<…>>` keyed by inode (`xattrs.rs`), never writing the backing FS. Entries are dropped on `forget`.
- Read-only is enforced **by the mount table (`MS_RDONLY`)**, not by FUSE: this is what lets the Nix daemon remount the store rw in its own namespace while everyone else sees a read-only overlay.
- Switch-root survival: the backing root directory fd is opened before mounting and the daemon `fchdir`s into it, so all backing paths resolve relative to that fd, never through the (soon stale) process root. The intended lifecycle follows systemd's ROOT_STORAGE_DAEMONS pattern: a paired "shadow" unit that never starts, plus `SurviveFinalKillSignal`/`RefuseManualStop`/`IgnoreOnIsolate`, stops PID1 from killing the daemon during switch-root/shutdown. `main.rs` logs and reports panics to `/dev/kmsg` (console-visible after journald stops).
- SELinux label routing: FUSE is not in the refpolicy's `fs_use` table, so without intervention `setxattr("security.selinux")` would short-circuit (`EOPNOTSUPP`) before reaching the daemon. SENix declares `fs_use_xattr fuse gen_context(system_u:object_r:fs_t,s0)` (in the `senix_store` base module) and mounts with `--seclabel` (sets `SBLABEL_MNT`), routing label ops into the in-memory store. **Never drop this declaration.**
- Installed also as `mount.fuse.metafs` so `mount -t fuse.metafs …` works from fstab/mount(8).

## Policy modules

- Policy modules are declared as `config.security.selinux.modules.<name>` in NixOS module files under `nixos/modules/`, each carrying:
  - `layer` (defaults to `senix`);
  - `interface` (`.if`), `typeEnforcement` (`.te`), `fileContext` (`.fc`) `rules` with `@attr@` expansion over `storePaths`, or `fileContext.source` for a verbatim `.fc` pulled from the refpolicy;
  - `name` defaults to the attribute name.
- `nixos/build.nix` overlays every declared module onto the pinned refpolicy source (`security.selinux.refpolicy.src`) and compiles the whole policy (`make conf` → policy.xml → `.pp`). A module whose **name+layer** combination already exists in the refpolicy source replaces the refpolicy file; anything else is a SENix-only module, placed in a generated `senix` layer and added to `modules.conf`. The layer is auto-detected by scanning the refpolicy tree.
- Module sources are materialized as store paths under `policy/modules/<layer>/` (`moduleSourceDrv`) so the build phase never has to copy huge inline strings (ARG_MAX).
- Custom modules must carry a `<summary>` doc comment in their `.if`, otherwise the refpolicy's `sedoctool.py` silently omits them from `modules.conf`.
- `senix_store` (`kernel` layer, marked `<required>`) is built into the **base** module, because `fs_use_xattr fuse` is only legal in the base — checkmodule rejects it in a loadable module. `senix_store` is the only place `fs_use` is declared.
- Store relabeling on `nixos-rebuild switch` is driven by the `selinux-policy` activation script: `semodule -i` over the built `.pp` set, removal of stale modules absent from the new build (so their labels revert), and `setsebool`; guarded by `/var/lib/selinux/activate-check` so it only re-runs when the command set changed.

## NixOS integration notes

- `boot.nixStoreMountOpts = lib.mkForce [ ]` — NixOS default (`ro nodev nosuid`) is deliberately dropped; metafs' ro remount replaces the stock `stage-2-init.sh` store bind mount for immutability. Guarded by an assertion.
- systemd is overridden `withSelinux`; the kernel gets `SECURITY_SELINUX` (`boot.kernelPatches`), `security.lsm = ["selinux"]`; `loop` is loaded early in both the host and initrd.
- `nixpkgs.overlays` re-builds a fixed set of packages with their SELinux flags (`withSelinux`/`selinuxSupport`) behind `overlayPackages` (coreutils excluded until upstream bootstrap supports it).
- `/etc/selinux/config` and `semanage.conf` are generated; `metafs`, `libselinux`, `policycoreutils` are installed into the system.

## Runtime tests

- `tests/selinux-enforce` — VM that boots permissive-mode and proves enforcement works: a confined domain can read its own data but is denied a secret file, and type transitions/relabels are verified.
- `tests/selinux-switch` — performs a real `nixos-rebuild switch` to a config where a module was removed and asserts the label reverts.
- `tests/metafs` — mounts metafs in a VM; exercises passthrough reads/writes/mutations, in-memory xattrs (incl. `security.selinux`), self-mount over its own source, and the `mount(8)` helper.
- `tests/screen` — reference for authoring a full custom module from `.te`/`.if`/`.fc` files (screen/tmux).

## Useful resources

- systemd ROOT_STORAGE_DAEMONS (daemon survival next to PID1): https://github.com/systemd/systemd/blob/main/docs/ROOT_STORAGE_DAEMONS.md
- systemd `relabel_extra()` / mount-time relabeling: `src/shared/mount-setup.c` (v261 sources).
- Refpolicy module instrumentation and base/required semantics: `support/sedoctool.py`, `support/segenxml.py` in the pinned refpolicy source (see `security.selinux.refpolicy.src`).
- NixOS store bind-mount options: `nixos/modules/system/boot/stage-2-init.sh` + `boot.nixStoreMountOpts` (upstream nixpkgs).
