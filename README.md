# SENix

**S**ecurity **E**nhanced **Nix** is an attempt to bring [SELinux](https://en.wikipedia.org/wiki/SELinux) to NixOS.

NixOS' design and core philosophy present some unique challenges when it comes to integrating something like SELinux.
This repository aims to overcome these challenges in form of a standalone NixOS module, and without requiring changes / patches to Nix itself.

Below you'll find some information on what this repository contains, rationale on the design, and why some (potentially strange-looking) things are necessary.

## Motivation

2026 has been a record year when it comes to the disclosure of security vulnerabilities in software.
As of 2026-11-25, we've been averaging around 300 CVEs per day, and we've already reached over 100,000 CVEs this year.
For reference, it took us from 1999 to 2018 to reach the first 100,000 CVEs.

With the rise of more and more capable AI, as well as autonomous systems to probe & exploit novel (0-day) vulnerabilities, the idea of securing systems on the application level alone seems more and more unrealistic.
These risks are exacerbated in environments where updating in a timely manner is not (always) possible.

It is therefore not only necessary to try our best to prevent unauthorized access to systems, but also to try and limit the impact of a compromise _when_ (not "if") it occurs.
Containerization & virtualization tools like Docker, hypervisors, or micro VMs already provide a good amount of isolation, but aren't always viable and sometimes even come with their own risks (such as access to the Docker socket effectively granting root rights).

Then there are approaches like systemd's sandboxing (via options like `ProtectStrict`), and flatpak on the desktop side of things.
The problem that all of these have in common is that they are explicitly opt-in and only cover specific apps that sysadmins think to enable them for.

This is where SELinux comes in.
Contrary to most other options, you don't use SELinux to take away apps' permissions, rather you use it to _grant_ them.
By default, everything is permissionless, and it's up to the policy designers to decide which processes are allowed to do what, and under which circumstances.

The policy system of SELinux is immensely complex, and trying to summarize it in a few sentences would do it injustice, so if you're interested in learning more about the core concepts in SELinux, I recommend taking a look at the [SELinux Notebook](https://github.com/selinuxproject/selinux-notebook).

## Roadmap

Ultimately, the goal is to have a fully functional SELinux integration in upstream NixOS.
However, there are still a few things to iron out before I would consider pursuing that, mainly:

- A well-defined and agreed upon structure / spec / schema for how we handle declarative SELinux modules.
  We already have an implementation of that, but since this is going to have a major influence on downstream modules & policies, it's not a decision I want to make alone.
- A policy that allows booting a fully functional NixOS system with SELinux in `enforcing mode`.
  In particular, I want _at minimum_ to support the "minimal" NixOS ISO, but ideally also the graphical one.
- Proper "production-ready" refactor of `metafs`, plus appropriate performance testing (more on the rationale in the relevant section below).
- Linux 7.4 needs to be released & in nixpkgs, due to a particular FUSE feature landing in it.
- A treewide `config.selinuxSupport` option in nixpkgs OR building all (relevant) packages with SELinux support by default.

## Overall architecture

The NixOS module's options are at `config.security.selinux`, with `config.security.selinux.enable` used to enable SEnix on a system.

SELinux modules are fully transcribed to NixOS modules, with their respective configuration placed under `config.security.selinux.modules.<name>`.
This makes it possible to compose / override module contents using familiar functions like `lib.mkForce`, `lib.mkBefore`, etc.

This repo houses the following types of modules:
- `nixos/modules/base` contains the modules that are automatically transcribed from the refpolicy
- `nixos/modules/targeted` contains SENix-specific overrides and/or additions to modules from the refpolicy
- `nixos/modules/custom` contains modules that are unique to SENix

### Current limitations / workarounds

- Pre-7.4 Linux kernels incorrectly perform speculative readahead on fd's opened in `FUSE_PASSTHROUGH` mode, so we currently carry a patch that backports that fix.
- nixpkgs currently builds most packages _without_ SELinux support by default, and doesn't (yet) have a config option to globally enable SELinux support, so enabling `config.security.selinux` instead adds an overlay to `nixpkgs.overlays` that enables SELinux support on various packages.
  Expect a decent amount of package rebuilds as a consequence.
- Since SELinux labels are only ever stored in memory, the entirety of `/nix/store` needs to be relabeled from scratch at every boot.
  This can take some time depending on your CPU, RAM, and number of files in the Nix store.

  We may add some form of caching to this in the future, but as of right now there are no concrete plans.
- SELinux directly conflicts with `config.nix.settings.auto-optimise-store`, since hardlinking files causes them to share the same inode.
  Since SELinux labels use xattrs, and xattrs are attached to inodes, this would require all hardlinked files to share the same labels, which would be an inconvenience at best and be a security flaw at worst.

  Although the MetaFS overlay makes each path appear as its own inode, even if the underlying filesystem has them hardlinked, and faithfully forwards `link` calls to the underlying filesystem, it is still recommended to disable auto store optimisation after every build, in order to reduce load.
  If you require minimizing disk usage of your Nix store, we recommend using filesystem-level deduplication instead, such as [`config.services.beesd`](https://search.nixos.org/options?channel=unstable&query=beesd&type=options#show=option%253Aservices.beesd.filesystems) for btrfs, or native ZFS deduplication.
  This also has the advantage of deduplicating your entire filesystem, instead of being focused solely on the Nix store.

### AI / LLM use

Much of this project has been developed with great assistance from LLMs, both during the research as well as the implementation phase.
During my development, I've had most core features be researched & drafted by an LLM, and then refined myself, or discarded.

There are some exceptions however:
- `metafs` is currently mostly LLM code, since it's still very much in the "throwing stuff out and seeing what sticks" phase.
  Once I get it to a point where I'm reasonably satisfied with it, I'm planning a manual refactor.
- `sepol2nix` and other dev tooling is 100% vibes, on purpose.
  Dev tooling & helper scripts is pretty much the best use case for vibe coding imo, and I don't care to perfect code that's never going to be production-facing.
- The NixOS VM tests are mostly vibes for the same reason.
  The only thing I ensure is that the LLMs aren't taking any shortcuts or making decisions that are so divorced from reality that it would render the tests useless, since they wouldn't faithfully represent a (potential) production system.

If you decide to work on this project with LLM assistance, **make sure they're not taking shortcuts**, because they can and will, given the opportunity.
I've had to fight so many times with agents who were insisting that adding a grant to `unlabeled_t` or `default_t` is "the only way" to fix a particular policy issue, even though that would largely defeat the entire purpose of SELinux, and many _will_ try to gaslight you, so be warned.

However, in my experience LLMs are much better (and more reserved) when it comes to drafting novel policies for applications from scratch.

Documentation / prose (incl. this readme) is not LLM generated, with the exception being the obvious "sticky notes" comments in certain places
These currently still exist to remind _me_ of why something is / was necessary, though these are all going to be cleaned up successively once parts of the policy approach more final states.

## System integration

### Policy loading

The SELinux policy is fully assembled inside the derivation that's exposed under `config.security.selinux.build.policy`.
It's integrated into the running system normally, using `environment.etc` and `boot.initrd.systemd.contents` respectively.

The policy is first loaded by the `selinux-init.service` during the initrd phase, which also labels a select few directories that have to be labeled correctly before the switchroot happens (e.g. systemd itself).
Upon switchroot, systemd itself then loads the policy and performs the necessary relabeling, including the `/nix/store`.

When activating a new system configuration, e.g. via `nixos-rebuild switch`, the new policy is symlinked to `/etc/selinux/targeted` via NixOS' own activation scripts, and then automatically loaded by systemd once it's triggered to reload.

### metafs

`metafs` is a bespoke FUSE filesystem, with its source sitting at `pkgs/metafs`.
Its entire job is to hold the `xattrs` of files (which is how SELinux labels things) in memory, and to hide the underlying inodes from applications.
Files are opened in FUSE_PASSTHROUGH mode, meaning operations on the resulting fd (e.g. read, write) completely bypass `metafs` and go straight to the underlying filesystem.

The latter is necessary because when a file is hardlinked, e.g. via `nix store optimise`, both hardlinks share the same inodes.
Since xattrs are stored on inodes, this would then require both files to share the same SELinux label, which causes breakage and may even present a security risk.

Holding the xattrs in memory may not strictly be necessary, since Nix is currently blind to them anyway, but it helps maintain the overall immutability of the Nix store.

The filesystem is mounted during the initrd phase, before `selinux-init.service` runs, and survives the switchroot.

> [!NOTE]
> 
> The current state of `metafs` is about 98% LLM code, and its performance impact also hasn't been benchmarked yet.
> I'm planning to rewrite the entire thing properly once I'm satisfied with its overall functionality.

### Automatic relabeling

SENix provides a systemd service for `restorecond`, a daemon that watches select paths for changes and automatically relabels files within them.

Since `/nix/store` in a SENix system is a FUSE filesystem, and FUSE filesystems currently don't support inotify events, the automatic relabeling of files in the store is handled via a post-build hook instead.

## Dev tooling

### sepol2nix

`sepol2nix` is a 100% vibe coded dev tool designed to help parse & transcribe SELinux modules to Nix.
Like `metafs`, it's written in Rust and its source sits at `pkgs/sepol2nix`.

There's also a companion script at `scripts/gen_base.py` that parses the modules from the refpolicy that's currently pinned in `nixos/refpolicy.nix` and generates the corresponding `.nix` files under `nixos/modules/base`.
This is necessary to ensure the entire system policy is fully declarative, and thus easier to compose / override by downstream consumers.

### `nixos/modules/targeted/apps/default.nix`

This one is a bit special, because it defines some helper functions.
The basic idea is to dynamically add modules to the system policy depending on which programs are enabled.
For example, only add thunderbird modules if you have `config.programs.thunderbird.enable` set to `true`.

This also allows us to specify the exact store paths of the relevant programs within the policy, to ensure only the _currently used_ version of a program receives the appropriate labels.

For apps that don't (yet) have a corresponding option under `config.programs`, the argument `addEnableOption` can be used to add one.

## Installation

You may wonder why the installation instructions are all the way at the bottom.
This is because everything in this repo is still very much experimental and subject to change (and probably also breakage).
For example, I've not yet tested `metafs` on an actual system with a busy Nix daemon and other processes that frequently interact with the store.
Thus, if you want to try it out, **I highly recommend doing so in a VM**.
If you _really_ want to test on real hardware, at least have a backup of your Nix store somewhere, or be prepared to repair it using the various Nix tools.

That said, if you want to enable SELinux on a system, simply set:

```nix
{
    config.security.selinux.enable = true;
}
```

And then rebuild your system, but **don't activate the new configuration yet** (i.e. run `nixos-rebuild boot` and NOT `nixos-rebuild switch`).
The reason for this is that the `metafs` filesystem needs to be mounted during the initrd phase, and before any relabeling happens.
However, if you use `nixos-rebuild switch` to transition from a non-SELinux system into an SELinux system, systemd will attempt to relabel the bare nix store instead (and likely fail at doing so).
Aside from that, there's currently also a mandatory kernel patch, so that alone is a reason to reboot.

Starting with the next boot, SELinux should now be active, with the policy loaded in `permissive` mode.
Now comes the point where you get to embark on the wonderful journey of using a combination of `journalctl`, `audit2allow`, and similar tools to figure out which permissions you need to grant to which processes, services, etc. in order to ensure your system remains functional when switching to `enforcing` mode later on.

Once you've done that, or once you think you're ready, you may switch to enforcing mode at any point, by setting:

```nix
{
    config.security.selinux.mode = "enforcing";
}
```

Note that only the policy mode _after_ the switchroot is affected by this, as SELinux during the initrd phase is always running in `permissive` mode.
This is mainly to avoid having to come up with rules that are only necessary during the initrd phase.
