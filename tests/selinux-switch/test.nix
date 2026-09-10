{ pkgs, ... }:
let
  # A trivial static store binary. The `switch_learn` module labels it
  # `switch_learn_exec_t`, so we can observe whether removing the module via a
  # real `switch` reverts the label (to unlabeled_t) or leaves a stale label.
  switchLearnApp =
    pkgs.runCommand "switch-learn"
      {
        nativeBuildInputs = [ pkgs.gcc ];
      }
      ''
        mkdir -p "$out/bin"
        cat > main.c <<'EOF'
        int main(void) { return 0; }
        EOF
        gcc -static -L${pkgs.glibc.static}/lib -o "$out/bin/switch-learn" main.c
      '';

  switchLearnModule = {
    security.selinux.modules.switch_learn = {
      typeEnforcement = ''
        policy_module(switch_learn)
        require {
          type init_t;
          type unconfined_t;
        }
        type switch_learn_exec_t;
        application_executable_file(switch_learn_exec_t)
        type switch_learn_t;
        init_domain(switch_learn_t, switch_learn_exec_t)
        type_transition unconfined_t switch_learn_exec_t:process switch_learn_t;
        allow unconfined_t switch_learn_exec_t:file execute;
        allow init_t switch_learn_exec_t:file execute;
      '';
      fileContext = {
        storePaths.switch_learn = [
          switchLearnApp
        ];
        rules = {
          "@switch_learn@/bin/switch-learn" = "gen_context(system_u:object_r:switch_learn_exec_t,s0)";
        };
      };
    };
  };

  baseModule =
    { lib, pkgs, ... }:
    {
      imports = [
        ../../nixos/default.nix
      ];
      nixpkgs.overlays = lib.mkForce [ ];
      systemd.package = pkgs.systemd.override {
        withSelinux = true;
      };
      security.selinux = {
        enable = true;
        mode = "enforcing";
      };
      environment.systemPackages = [
        pkgs.attr
        pkgs.policycoreutils
      ];
    };

  # Only applied to the host-built switch target, not the test machine (whose
  # filesystem and boot loader are provided by the runNixOSTest framework).
  c2FilesystemModule = {
    fileSystems."/" = {
      device = "/dev/disk/by-label/nixos";
      fsType = "ext4";
    };
    boot.loader.grub.device = "nodev";
    boot.loader.grub.enable = true;
  };

  # The host-built "module removed" configuration this test switches to, so the
  # activation scripts (semodule + selinux-relabel) run for a *different* policy
  # and file-context set, not just an idempotent re-apply.
  c2 =
    (pkgs.nixos [
      baseModule
      c2FilesystemModule
    ]).config.system.build.toplevel;

  # Pull `c2` (and its closure) into the machine's store so the test can switch
  # to it without a host-to-guest copy (`copy_from_host` cannot follow the
  # toplevel's dangling absolute symlinks such as `/etc/fonts/fonts.conf`).
  machineModules = [
    baseModule
    switchLearnModule
    {
      environment.systemPackages = [
        c2
      ];
    }
  ];
in
pkgs.testers.runNixOSTest {
  name = "selinux-switch";
  nodes.machine =
    { lib, pkgs, ... }:
    {
      imports = machineModules;
    };

  testScript =
    # python
    ''
      machine.wait_for_unit("multi-user.target")

      # With the module present at boot, the binary must carry its label.
      machine.succeed(
          "getfattr -n security.selinux --only-values ${switchLearnApp}/bin/switch-learn | grep -q switch_learn_exec_t"
      )
      # The boot-time relabel must also cover a non-store home directory. The
      # refpolicy home rules use `HOME_DIR` macros, which setfiles expands from
      # the real user homes, so a created home dir must get a home context.
      machine.succeed("mkdir -p /home/selinuxtest")
      machine.succeed("selinux-relabel")
      machine.succeed("getfattr -n security.selinux --only-values /home/selinuxtest")
      machine.succeed(
          "getfattr -n security.selinux --only-values /home/selinuxtest | grep -qE 'user_home_dir_t|user_home_t|home_root_t'"
      )

      # A `nixos-rebuild switch` to a configuration that no longer declares the
      # module (its toplevel is already in the machine store). This runs the
      # activation: it reloads the policy (semodule) and re-applies labels
      # (selinux-relabel) for the new, smaller file-context set.
      machine.succeed("switch-to-configuration switch ${c2}")

      # After the switch the module's type is absent from the policy, so the
      # binary must not still carry `switch_learn_exec_t` (it reverts to
      # unlabeled_t rather than keeping a stale label).
      machine.succeed(
          "! getfattr -n security.selinux --only-values ${switchLearnApp}/bin/switch-learn | grep -q switch_learn_exec_t"
      )
    '';
}
