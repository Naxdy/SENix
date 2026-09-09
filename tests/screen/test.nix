{ pkgs, ... }:
pkgs.testers.runNixOSTest {
  name = "selinux-screen";

  nodes.machine =
    { lib, pkgs, ... }:
    {
      imports = [
        ./module.nix
        ../../nixos/default.nix
      ];

      # `runNixOSTest` drives the machine with a pre-built, read-only `pkgs`, so
      # the SELinux package overrides declared in the module can not be applied
      # here (they are irrelevant for the store-xattr assertions below). Forcing
      # the empty overlays instead of defining them avoids a read-only conflict.
      nixpkgs.overlays = lib.mkForce [ ];

      environment.systemPackages = [
        pkgs.screen
        pkgs.tmux
        pkgs.attr
      ];
    };

  testScript =
    # python
    ''
      machine.wait_for_unit("multi-user.target")

      # `command -v` resolves through /run/current-system; dereference to the
      # (read-only) Nix store path so we assert on the actual store object that
      # the SquashFS metadata overlay is meant to label.
      screen_bin = machine.succeed("readlink -f \"$(command -v screen)\"").strip()
      tmux_bin = machine.succeed("readlink -f \"$(command -v tmux)\"").strip()

      # A `nixos-rebuild switch` with a different `build.squashfs` re-runs the
      # same overlay setup (the activation script runs the `selinux-store-overlay`
      # command). Since the boot already mounted the current squashfs, force the
      # "changed squashfs" path by marking it stale, then re-apply and check the
      # labels are still correct after the reconfigure.
      machine.succeed("echo stale > /run/selinux/store-overlay-squashfs")
      machine.succeed("selinux-store-overlay")

      with subtest("the screen binary carries the screen_exec_t context"):
          machine.succeed(
              "getfattr -n security.selinux --only-values \"%s\" | grep -q screen_exec_t" % screen_bin
          )

      with subtest("the tmux binary carries the screen_exec_t context"):
          machine.succeed(
              "getfattr -n security.selinux --only-values \"%s\" | grep -q screen_exec_t" % tmux_bin
          )

    '';
}
