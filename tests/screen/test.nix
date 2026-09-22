{ senix, testers, ... }:
testers.runNixOSTest {
  name = "selinux-screen";

  node.pkgsReadOnly = false;

  nodes.machine =
    { lib, pkgs, ... }:
    {

      imports = [
        ./module.nix
        senix
      ];

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
      # the boot-time relabel is meant to label.
      screen_bin = machine.succeed("readlink -f \"$(command -v screen)\"").strip()
      tmux_bin = machine.succeed("readlink -f \"$(command -v tmux)\"").strip()

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
