{
  pkgs,
  senix,
  testers,
  ...
}:
let
  # A fixed-output derivation replicating `pkgs.curl.src` (an `outputHashMode
  # = "flat"` fetchurl FOD), evaluated *inside the guest* from the store's own
  # `<nixpkgs>`, so it carries real string contexts: the builder, coreutils and
  # curl are resolved in the guest's store and the sandbox exposes exactly the
  # closure of the derivation's inputs. Nothing about the output exists in the
  # store until the guest builds it.
  #
  # The `outputHash` / `outputHashMode` attributes are copied verbatim from the
  # original derivation at guest eval time (`tarball.outputHash*`), so the
  # daemon's post-build hash verification uses the exact declared hash and mode
  # that upstream nixpkgs established on a store without metafs. We only swap
  # the URL for `file://` + the tarball's store path so the test is hermetic;
  # curl then copies the *same bytes* the hash was computed from, and the whole
  # pipeline (download through the sandbox's bind of the store, output written
  # through metafs, hash verification by the daemon through the daemon's rw
  # remount of the metafs overlay) runs on top of metafs.
  mkFod =
    { suffix, hash }:
    pkgs.writeText "senix-fod${suffix}.nix" ''
      let
        pkgs = import <nixpkgs> { };
        tarball = pkgs.curl.src;
      in
      builtins.derivation {
        name = "''${tarball.name}${suffix}";
        system = "''${pkgs.stdenv.hostPlatform.system}";
        builder = "''${pkgs.runtimeShell}";
        args = [
          "-ec"
          "exec ''${pkgs.curl}/bin/curl --location --fail --output \"$out\" \"$url\""
        ];
        url = "file://''${tarball}";
        outputHash = ${hash};
        outputHashMode = "''${tarball.outputHashMode}";
      }
    '';

  fodGood = mkFod {
    suffix = "-senix-rebuild";
    hash = "tarball.outputHash";
  };
  fodUnsandboxed = mkFod {
    suffix = "-senix-rebuild-unsandboxed";
    hash = "tarball.outputHash";
  };
  fodWrongHash = mkFod {
    suffix = "-senix-wrong-hash";
    hash = ''"sha256:" + builtins.hashString "sha256" "senix-not-the-curl-tarball"'';
  };
in
testers.runNixOSTest {
  name = "fixed-output";

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

      # The tarball and curl must be valid in the guest's store before the
      # guest can evaluate and build the fixed-output derivation offline.
      system.extraDependencies = [
        pkgs.curl
        pkgs.curl.src
      ];

      environment.systemPackages = [
        pkgs.attr
      ];
    };

  testScript =
    # python
    ''
      machine.wait_for_unit("multi-user.target")

      nix = "nix --extra-experimental-features nix-command"
      nix_env = "NIX_PATH=nixpkgs=${pkgs.path}"
      tarball = "${pkgs.curl.src}"

      with subtest("metafs serves the store and the tarball carries a label"):
          machine.succeed("test \"$(getenforce)\" = Enforcing")
          # Reading a label for a store path goes through metafs' in-memory
          # xattr map — the same surface the daemon sees from its rw remount.
          machine.succeed(f"getfattr -n security.selinux --only-values {tarball} | grep -q '^system_u:'")

      with subtest("the fixed-output derivation builds and matches the known hash"):
          machine.succeed(f"{nix_env} {nix} build --impure -f ${fodGood} --no-link -L")
          out = machine.succeed(f"{nix_env} {nix} eval --impure --raw -f ${fodGood} outPath").strip()
          print("[senix] FOD output:", out)
          # flat hash mode: the daemon hashed the output's content, read back
          # through the metafs passthrough, against the declared sha256.
          machine.succeed(f"cmp {out} {tarball}")
          # The post-build hook relabeled the fresh output through metafs as well.
          machine.succeed(f"getfattr -n security.selinux --only-values {out} | grep -q '^system_u:'")

      with subtest("rebuilding after deleting the output reproduces the hash"):
          machine.succeed(f"{nix} store delete {out}")
          machine.fail(f"{nix} path-info {out}")
          machine.succeed(f"{nix_env} {nix} build --impure -f ${fodGood} --no-link -L")
          machine.succeed(f"cmp {out} {tarball}")

      with subtest("an unsandboxed build (builder inside the daemon's rw remount) also verifies"):
          machine.succeed(f"{nix_env} {nix} build --impure --option sandbox false -f ${fodUnsandboxed} --no-link -L")
          out_unsandboxed = machine.succeed(
              f"{nix_env} {nix} eval --impure --raw -f ${fodUnsandboxed} outPath"
          ).strip()
          print("[senix] unsandboxed FOD output:", out_unsandboxed)
          machine.succeed(f"cmp {out_unsandboxed} {tarball}")

      with subtest("a wrong declared hash fails the build with a hash mismatch"):
          machine.succeed(
              f"{nix_env} {nix} build --impure -f ${fodWrongHash} --no-link 2>/tmp/senix-fod-stderr || true"
          )
          stderr = machine.succeed("cat /tmp/senix-fod-stderr")
          print("[senix] wrong-hash build stderr:", stderr.strip())
          assert "hash mismatch" in stderr.lower(), stderr

      # Informational only: policy denials observed while the builds ran.
      print(
          "[senix] AVC denials during test:",
          machine.succeed("journalctl -k --no-pager | grep -c 'avc:.*denied' || true").strip(),
      )
    '';
}
