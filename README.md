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

---

This project was / is being built with heavy assistance from AI agents, but the core design decisions are made by a human.
You do not want to know how many times I had to yell "stop fucking extending the permissions of `unlabeled_t`" or "stop cheating with making processes unconfined".
