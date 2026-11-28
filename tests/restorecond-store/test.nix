{
  pkgs,
  senix,
  testers,
  ...
}:
let
  # Evaluated inside the guest from the store's own `<nixpkgs>`, so the
  # derivation carries real string contexts for its builder and tools — the
  # build sandbox only exposes the *closure of the derivation's inputs*. Its
  # output is deliberately not referenced by the system closure, so it does not
  # exist in the store until the test builds it.
  #
  # The output deliberately has both a `bin/` file (which the reference policy
  # maps to `bin_t`) and a plain file (which falls through to `usr_t`).
  probeFile = pkgs.writeText "restorecond-probe.nix" ''
    let
      pkgs = import <nixpkgs> { };
    in
    builtins.derivation {
      name = "restorecond-probe";
      system = "''${pkgs.stdenv.hostPlatform.system}";
      builder = "''${pkgs.runtimeShell}";
      args = [
        "-c"
        "set -eux; export PATH=''${pkgs.coreutils}/bin; mkdir -p $out/bin; echo probe > $out/bin/probe; echo data > $out/data.txt"
      ];
    }
  '';
in
testers.runNixOSTest {
  name = "restorecond-store";

  node.pkgsReadOnly = false;

  nodes.machine =
    { pkgs, ... }:
    {
      imports = [
        senix
      ];
      boot.kernelPackages = pkgs.linuxPackages_testing;

      security.selinux = {
        enable = true;
        mode = "enforcing";
        overlayPackages = false;
      };

      environment.systemPackages = [
        pkgs.attr
        pkgs.policycoreutils
      ];
    };

  testScript =
    # python
    ''
      machine.wait_for_unit("multi-user.target")

      with subtest("SELinux and restorecond are up with the base policy only"):
          machine.succeed("test \"$(getenforce)\" = Enforcing")
          machine.succeed("systemctl is-active restorecond.service")

      # `<nixpkgs>` for the evaluation of the probe expression. Naming the source
      # here also pulls it into the test's store closure.
      nixpkgs = "${pkgs.path}"
      nix = "nix --extra-experimental-features nix-command"

      # The store hash of a derivation that has not been built yet.
      store_path = machine.succeed(
          "NIX_PATH=nixpkgs=%s %s eval --impure --raw -f ${probeFile} outPath" % (nixpkgs, nix)
      ).strip()
      print("[senix] probe store path:", store_path)
      basename = store_path.rsplit("/", 1)[-1]

      with subtest("the derivation's output is not in the store yet"):
          # Query the store database rather than the filesystem: a doomed
          # `test -e` here would leave a negative dentry for the output path.
          machine.fail("%s path-info %s" % (nix, store_path))

      with subtest("nix builds it at runtime"):
          machine.succeed(
              "NIX_PATH=nixpkgs=%s %s build --impure --no-link -f ${probeFile}" % (nixpkgs, nix)
          )
          machine.succeed("test -e %s/bin/probe" % store_path)

      with subtest("the freshly built store path is labeled"):
          # The post-build hook relabels the build's outputs. `bin/` keeps the
          # reference policy's `bin_t` mapping ...
          machine.succeed(
              "getfattr -n security.selinux --only-values %s/bin/probe | grep -q bin_t" % store_path
          )
          # ... while everything else (including the store entry itself) is `usr_t`.
          machine.succeed(
              "getfattr -n security.selinux --only-values %s/data.txt | grep -q usr_t" % store_path
          )
          machine.succeed(
              "getfattr -n security.selinux --only-values %s | grep -q usr_t" % store_path
          )

      with subtest("the backing store below the metafs mount gets no xattrs"):
          # The metafs daemon `fchdir`s into its backing directory before mounting
          # itself over the path, so its `/proc/<pid>/cwd` is exactly the real
          # filesystem the overlay is layered on.
          metafs_pid = machine.succeed(
              "for p in $(pgrep -x metafs); do test -e /proc/$p/cwd/%s && { echo $p; break; }; done"
              % basename
          ).strip()
          assert metafs_pid, "no metafs process backs %s" % store_path
          backing = "/proc/%s/cwd/%s" % (metafs_pid, basename)

          machine.succeed("test -e %s/bin/probe" % backing)
          machine.succeed("test -e %s/data.txt" % backing)
          # Neither the SELinux label nor any other xattr may have leaked through.
          machine.fail(
              "getfattr -d %s/bin/probe %s/data.txt 2>/dev/null | grep -qE '^(security|user)[.]'"
              % (backing, backing)
          )
    '';
}
