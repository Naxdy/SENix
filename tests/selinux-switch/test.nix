{
  senix,
  runCommand,
  gcc,
  glibc,
  testers,
}:
testers.runNixOSTest (
  { config, ... }:
  let
    # A trivial static store binary. The `switch_learn` module labels it
    # `switch_learn_exec_t`, so we can observe whether dropping the module in a
    # switch recomputes the label from the new file contexts or leaves the stale
    # (now unmapped) one behind.
    switchLearnApp =
      runCommand "switch-learn"
        {
          nativeBuildInputs = [ gcc ];
        }
        ''
          mkdir -p "$out/bin"
          cat > main.c <<'EOF'
          int main(void) { return 0; }
          EOF
          gcc -static -L${glibc.static}/lib -o "$out/bin/switch-learn" main.c
        '';

    # The module under test, behind a flag so that the switch target below can
    # drop it: with the flag off, `mkIf` removes the
    # `security.selinux.modules.switch_learn` definition outright, so the target
    # really builds a policy *without* the module instead of one whose rules
    # were stripped.
    switchLearnModule =
      { config, lib, ... }:
      {
        options.senix.test.switchLearn = lib.mkOption {
          type = lib.types.bool;
          default = true;
          description = ''
            Whether the test-only `switch_learn` policy module is part of the
            policy.
          '';
        };

        config.security.selinux.modules.switch_learn = lib.mkIf config.senix.test.switchLearn {
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

    # The configuration this test switches to.
    #
    # It has to be an *exact replica* of the machine's own configuration:
    # `switch-to-configuration` diffs the running system against the incoming
    # one and stops/restarts every unit that differs, and unmounts every fstab
    # entry that disappeared. A hand-rolled configuration that merely
    # approximates the test machine — no `virtualisation.qemu-vm`, no test
    # instrumentation, no generated `fileSystems` — differs in most units and in
    # `/etc/fstab`, so the switch stops `nix-store.mount` and friends, i.e. it
    # tries to unmount the store the incoming system itself lives in.
    #
    # A `specialisation` with `inheritParentConfig` (its default) *is* the
    # machine configuration re-evaluated with one extra module, so the two
    # systems differ in exactly what is declared below. Its toplevel is linked
    # into the machine's toplevel (`$out/specialisation/<name>`), so it is built
    # as part of the machine's closure and present in the guest's store before
    # the switch.
    target = config.nodes.machine.specialisation.target.configuration.system.build.toplevel;
  in
  {
    name = "selinux-switch";

    node.pkgsReadOnly = false;

    nodes.machine =
      { pkgs, ... }:
      {
        imports = [
          senix
          switchLearnModule
        ];

        security.selinux = {
          enable = true;
          mode = "permissive";
          overlayPackages = false;
        };

        environment.systemPackages = [
          pkgs.attr
          pkgs.policycoreutils
        ];

        specialisation.target.configuration = {
          # The module under test is gone: its type leaves the policy and the
          # binary's label must revert.
          senix.test.switchLearn = false;

          # A change with no effect on the rest of the system, so that a switch
          # into the target is observable even if the policy side is broken.
          environment.etc."senix-switch-target".text = "switched\n";
        };
      };

    testScript =
      # python
      ''
        # Boot first: the store metadata only labels the store by the time the
        # relabel runs, so the transient `unlabeled_t` unit files during early boot
        # are handled by the init/initrc `service` access granted in the `libs`
        # module.
        machine.wait_for_unit("multi-user.target")

        machine.succeed(
            "getfattr -n security.selinux --only-values $(readlink -f /etc/systemd/system/multi-user.target)"
            + " | grep -q systemd_unit_t"
        )

        # With the module present at boot, the binary must carry its label.
        machine.succeed(
            "getfattr -n security.selinux --only-values ${switchLearnApp}/bin/switch-learn | grep -q switch_learn_exec_t"
        )
        # The boot-time relabel must also cover a non-store home directory. The
        # refpolicy home rules use `HOME_DIR` macros, which setfiles expands from
        # the real user homes, so a created home dir must get a home context.
        machine.succeed("mkdir -p /home/selinuxtest")
        machine.succeed("getfattr -n security.selinux --only-values /home/selinuxtest")
        machine.succeed(
            "getfattr -n security.selinux --only-values /home/selinuxtest | grep -qE 'user_home_dir_t|user_home_t|home_root_t'"
        )

        # The *target's* `switch-to-configuration`, like `nixos-rebuild` does: the
        # wrapper carries the `OUT`/`TOPLEVEL` of the system it belongs to, so
        # invoking it activates the target. `test` is the documented action for
        # switching into a specialisation
        # <https://nixos.org/manual/nixos/unstable/#module-system-activation-script>:
        # it runs the full activation (relabel + `semodule`, the etc switch, the
        # unit diff), which is what this test is about. `switch` would
        # additionally install a boot loader and make the target the boot
        # default, which is meaningless for a specialisation.
        machine.succeed("${target}/bin/switch-to-configuration test")
        machine.wait_until_succeeds(
            "test \"$(readlink -f /run/current-system)\" = ${target}"
        )

        # The switch must not have touched the store mount: /nix/store is still
        # the metafs overlay, not unmounted (or replaced by the backing mount).
        machine.succeed("grep -q ' /nix/store fuse ' /proc/mounts")

        # The incoming system's /etc is live.
        machine.succeed("grep -q switched /etc/senix-switch-target")

        # The module is absent from the incoming policy, so the binary must no
        # longer carry `switch_learn_exec_t`. Store labels live in metafs'
        # in-memory map, so they only follow a policy change if something
        # recomputes them from the new file contexts — on a switch that is the
        # store relabel the `selinux-policy` activation script runs (the initrd
        # relabel that set this label never runs again). A stale label here means
        # the path keeps naming a type the policy no longer defines.
        machine.succeed(
            "lbl=$(getfattr -n security.selinux --only-values ${switchLearnApp}/bin/switch-learn 2>/dev/null | tr -d '\\0'); "
            "if echo \"$lbl\" | grep -q switch_learn_exec_t; then echo \"STALE: $lbl\"; exit 1; fi"
        )
      '';
  }
)
