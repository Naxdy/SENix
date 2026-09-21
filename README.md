# SENix

**S**ecurity **E**nhanced **Nix** is an attempt to bring [SELinux](https://en.wikipedia.org/wiki/SELinux) to NixOS.

The current state is an extremely crude, but technically functional PoC implementation of SELinux.
The following is a list of minimum requirements that _have_ to be in place before we can even think of upstreaming:

- [x] Provide NixOS modules for configuring SELinux and the system policy declaratively
- [x] Initialize SELinux and the policy during the initrd phase
- [x] Mount a metacopy overlay over the sysroot's `/nix/store` to allow setting xattrs without touching the real Nix store.
      Note that this _replaces_ NixOS' builtin stage-2 readonly remount.
- [x] Apply required labels to the sysroot's systemd and packages in the initrd's `/nix/store`
- [x] Specify directories that need relabeling for the handoff to systemd, which handles the bulk of relabeling post-initd
- [x] Have systemd transition into the correct domain (`init_t`) and relabel the host system
- [x] Provide SELinux rules & modules to facilitate booting a NixOS VM in enforcement mode (see `tests/selinux-enforce`)
- [ ] Allow multiple entries per path in `config.security.selinux.modules.*.fileContext.rules`
- [ ] Declaratively flag duplicate wildcards within the same layers for `.fc` rules
- [ ] Add systemd service for `restorecond`
- [x] Replace the `tmpfs` metacopy overlay with a bespoke FUSE filesystem to allow returning `EROFS` on write attempts
      (see `./metafs`). The store stays strictly read-only: every mutation returns `EROFS`, while extended
      attributes are kept in an in-memory map so SELinux can still label store objects without touching
      the real Nix store.
- [ ] Migrate more `.fc` modules from the refpolicy and integrate them into the module system
- [ ] Add more modules for things that need it, e.g. Nix itself, core system components
- [ ] Decide on a framework to reliably facilitate `nixos-rebuild switch` (completely untested atm)
- [ ] Make the policy build check for more issues at build time; right now e.g. invalid type references are only caught
      upon attempting to initialize it.
- [ ] Migrate the entire refpolicy to Nix (?)
- [ ] Actually test on a _real_ system

NOT planned for now / out of scope:

- Non-MCS / MLS-enabled policies

## Caveats

- Since SELinux labels are only ever stored in memory, the entirety of `/nix/store` needs to be relabeled from scratch at every boot.
  This can take some time depending on your CPU, RAM, and number of files in the Nix store.

  We may add some form of caching to this in the future, but as of right now there are no concrete plans.

- Certain policy errors (e.g. importing nonexistent types) are only caught at runtime, meaning a `nixos-rebuild switch` with a policy that's broken in such a way could lead to a non-enforcing state.

  The solution to this would be to fully compile the policy within the Nix derivation itself, but this can only be done with extensive workarounds.

- SELinux directly conflicts with `config.nix.settings.auto-optimise-store`, since hardlinking files causes them to share the same inode.
  Since SELinux labels use xattrs, and xattrs are attached to inodes, this would require all hardlinked files to share the same labels, which would be an inconvenience at best and be a security flaw at worst.

  Although the MetaFS overlay makes each path appear as its own inode, even if the underlying filesystem has them hardlinked, and faithfully forwards `link` calls to the underlying filesystem, it is still recommended to disable auto store optimisation after every build, in order to reduce load.
  If you require minimizing disk usage of your Nix store, we recommend using filesystem-level deduplication instead, such as [`config.services.beesd`](https://search.nixos.org/options?channel=unstable&query=beesd&type=options#show=option%253Aservices.beesd.filesystems) for btrfs, or native ZFS deduplication.
  This also has the advantage of deduplicating your entire filesystem, instead of being focused solely on the Nix store.

---

This project was / is being built with heavy assistance from AI agents, but the core design decisions are made by a human.
You do not want to know how many times I had to yell "stop fucking extending the permissions of `unlabeled_t`" or "stop cheating with making processes unconfined".
