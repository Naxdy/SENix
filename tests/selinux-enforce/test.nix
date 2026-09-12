{ pkgs, ... }:
let
  # A tiny static binary that tries to open the allowed data file and the secret
  # file. SELinux enforcement means the `enforce_learn_t` domain can open
  # `allowed` (enforce_learn_data_t) but `open` on `secret`
  # (enforce_learn_secret_t) is denied (no allow rule -> EACCES).
  enforceLearnApp =
    pkgs.runCommand "enforce-learn"
      {
        nativeBuildInputs = [ pkgs.gcc ];
      }
      ''
        mkdir -p "$out/bin"
        cat > main.c <<'EOF'
        #include <fcntl.h>
        #include <stdio.h>
        #include <unistd.h>
        int main(void) {
            int allowed = open("/var/lib/enforce_learn/allowed", O_RDONLY);
            int secret = open("/var/lib/enforce_learn/secret", O_RDONLY);
            char dom[64] = {0};
            int fd = open("/proc/self/attr/current", O_RDONLY);
            if (fd >= 0) {
                read(fd, dom, sizeof(dom) - 1);
                close(fd);
            }
            printf("allowed_readable=%d secret_readable=%d domain=%s\n", allowed >= 0, secret >= 0, dom);
            /* Success: it can read its own data, and cannot read the secret. */
            return (allowed >= 0 && secret < 0) ? 0 : 1;
        }
        EOF
        gcc -static -L${pkgs.glibc.static}/lib -o "$out/bin/enforce-learn" main.c
      '';
in
pkgs.testers.runNixOSTest {
  name = "selinux-enforce";

  nodes.machine =
    { lib, pkgs, ... }:
    {
      imports = [
        ../../nixos/default.nix
      ];

      security.selinux = {
        enable = true;
        mode = "permissive";
        overlayPackages = false;

        modules.enforce_learn = {
          typeEnforcement = ''
            policy_module(enforce_learn)

            require {
              type init_t;
              type initrc_t;
              type kernel_t;
              type unconfined_t;
              type tty_device_t;
              type var_t;
              type var_lib_t;
              type unlabeled_t;
              type fs_t;
            }

            type enforce_learn_exec_t;
            application_executable_file(enforce_learn_exec_t)

            type enforce_learn_t;
            init_domain(enforce_learn_t, enforce_learn_exec_t)

            # The test invokes the binary directly; allow the likely caller
            # domains to enter the confined domain via a type transition.
            type_transition unconfined_t enforce_learn_exec_t:process enforce_learn_t;
            allow unconfined_t enforce_learn_exec_t:file execute;
            allow init_t enforce_learn_exec_t:file execute;
            type_transition init_t enforce_learn_exec_t:process enforce_learn_t;
            # The test's shell/backdoor runs as `initrc_t`; let it also enter the
            # confined domain when it execs the binary (matching the script below,
            type_transition initrc_t enforce_learn_exec_t:process enforce_learn_t;
            allow initrc_t enforce_learn_exec_t:file execute;
            allow initrc_t enforce_learn_t:process transition;
            allow kernel_t enforce_learn_t:process transition;
            type_transition kernel_t enforce_learn_exec_t:process enforce_learn_t;
            allow kernel_t enforce_learn_exec_t:file execute;

            type enforce_learn_data_t;
            files_type(enforce_learn_data_t)

            type enforce_learn_secret_t;
            # Make it a `files_type` so the relabeling shell (initrc_t) can
            # `setfattr` the secret file (the data type is a files_type too).
            files_type(enforce_learn_secret_t)
            # The app handles the stdio it inherited from the caller (the test
            # driver's shell, which is `kernel_t`) and the console it is bound
            # to; without these it cannot even print to stdout.
            allow enforce_learn_t kernel_t:fd use;
            allow enforce_learn_t unconfined_t:fd use;
            allow enforce_learn_t init_t:fd use;
            allow enforce_learn_t initrc_t:fd use;
            allow enforce_learn_t tty_device_t:chr_file { read write };
            allow enforce_learn_t kernel_t:fifo_file rw_fifo_file_perms;

            # Resolve `/var/lib/enforce_learn/...`: traverse the (unlabelled)
            # root filesystem directories.
            allow enforce_learn_t unlabeled_t:dir { read search open };
            allow enforce_learn_t var_t:dir { read search open };
            allow enforce_learn_t var_lib_t:dir { read search open };
            allow enforce_learn_t self:process signal_perms;
            allow enforce_learn_t self:fd use;
            allow enforce_learn_t enforce_learn_data_t:file { open read getattr };
            allow enforce_learn_data_t fs_t:filesystem associate;
            allow enforce_learn_secret_t fs_t:filesystem associate;

            # The test driver labels the app's data files with `setfattr`; it
            # runs as `init_t` (systemd), so grant it the relabel permission.
            allow init_t enforce_learn_data_t:file relabelto;
            allow init_t enforce_learn_secret_t:file relabelto;
          '';
          fileContext = {
            storePaths.enforce_learn = [
              enforceLearnApp
            ];
            rules = {
              "@enforce_learn@/bin/enforce-learn" = "gen_context(system_u:object_r:enforce_learn_exec_t,s0)";
            };
          };
        };
      };
      environment.systemPackages = [
        pkgs.attr
        pkgs.policycoreutils
        pkgs.setools
      ];
    };

  testScript =
    # python
    ''
      machine.wait_for_unit("multi-user.target")

      status, out = machine.execute(
          "ls -la /etc/selinux/refpolicy >&1 2>&1; readlink /etc/selinux/refpolicy 2>&1; "
          "ls -la /run/selinux/refpolicy/contexts/files/ >&1 2>&1; "
          "wc -l /etc/selinux/refpolicy/contexts/files/file_contexts >&1 2>&1; "
          "grep -c init_exec_t /etc/selinux/refpolicy/contexts/files/file_contexts 2>&1; "
          "grep -E 'systemd-261.2/lib/systemd/systemd($|[^ ])' /etc/selinux/refpolicy/contexts/files/file_contexts 2>&1 | head -5; "
          "readlink -f /etc/systemd/system/selinux-relabel.service 2>&1; "
          "getfattr -n security.selinux --only-values $(readlink -f /etc/systemd/system/selinux-relabel.service) 2>&1"
      )
      print("POSTBOOT FC LAYOUT:\n" + out)

      # The initrd `selinux-init` relabel must label the store unit files
      # `systemd_unit_t` before switch_root (including the NixOS-generated
      # `*-unit-*` packages), so systemd can manage them.
      status, out = machine.execute(
          "getfattr -n security.selinux --only-values $(readlink -f /etc/systemd/system/selinux-relabel.service)"
      )
      print("RELABEL UNIT LABEL:\n" + out)

      status, out = machine.execute(
          "echo PID1=$(cat /proc/1/attr/current 2>&1); "
          "echo PID1_EXE=$(readlink /proc/1/exe 2>&1); "
          "shopt -s nullglob; for p in /nix/store/*-systemd-*/lib/systemd/systemd "
          "/nix/store/*-systemd-*/lib/systemd/systemd-executor "
          "/run/current-system/systemd/lib/systemd/systemd "
          "/run/current-system/systemd/lib/systemd/systemd-executor; do "
          "echo \"SYSD $p CTX=$(getfattr -h -n security.selinux --only-values $p 2>&1)\"; done; "
          "shopt -u nullglob"
      )
      print("PID1 + SYSTEMD:\n" + out)
      status, out = machine.execute("grep ' /nix/store ' /proc/self/mountinfo | grep -oE 'lowerdir=[^ ]*|upperdir=[^ ]*|metacopy[^ ]*|/nix/.ro-store|/sysroot/nix/.ro-store'")
      print("STORE MOUNTINFO:\n" + out)
      status, out = machine.execute("getfattr -n security.selinux --only-values /nix/store/rmckqiyjhrg8napr86fgvvkkwm8s29qa-enforce-learn/bin/enforce-learn 2>&1; echo ---; getfattr -n security.selinux --only-values /nix/store/mwq3vsf8vjb3lpfz0czy0vk9j98dyxda-unit-script-selinux-relabel-start/bin/selinux-relabel-start 2>&1")
      print("STORE BIN CONTEXTS:\n" + out)
      status, out = machine.execute("journalctl -k --no-pager -n 200 | grep -iE 'relabel|selinux|avc|denied|exec|init_unit'")
      print("KERNEL AVC:\n" + out)
      status, out = machine.execute("semodule -l 2>&1 | grep -iE 'selinux_tools|selinuxutil|init_context|enforce_learn|base|^init '")
      print("MODULES:\n" + out)
      # The `init_t -> init_unit_t` transition is denied by the kernel even
      # though `selinux_tools` is loaded; inspect the loaded policy binary.
      status, out = machine.execute(
          "sesearch -A -s init_t -t init_unit_t -c process -p transition /run/selinux/refpolicy/active/policy.kern 2>&1"
      )
      print("SESEARCH transition:\n" + out)
      status, out = machine.execute("seinfo -a domain /run/selinux/refpolicy/active/policy.kern 2>&1 | grep -E 'init_t|init_unit_t'")
      print("INIT_UNIT_IN_DOMAIN:\n" + out)
      status, out = machine.execute("seinfo -t init_unit_t /run/selinux/refpolicy/active/policy.kern 2>&1")
      print("INIT_UNIT_TYPE:\n" + out)
      status, out = machine.execute("getfattr -n security.selinux --only-values /nix/store/9qnvy6p5i1zzcsn669bd4ykivippqhzl-unit-script-selinux-relabel-start/bin/selinux-relabel-start 2>&1")
      print("RELABEL BIN CTX:\n" + out)
      status, out = machine.execute(
          "grep -nE 'enforce-learn|/nix/store' /run/selinux/refpolicy/active/file_contexts 2>&1 | tail -30"
      )
      print("FC ENFORCE:\n" + out)
      status, out = machine.execute(
          "find / \\( -name file_contexts -o -name policy.kern -o -name 'policy.3*' \\) -print 2>/dev/null"
      )
      print("FC POLICY PATHS:\n" + out)
      machine.wait_for_unit("selinux-relabel.service")
      status, out = machine.execute("ls -la /run/selinux/refpolicy/active/file_contexts 2>&1; echo ---; grep -cE 'enforce_learn|nix/store' /run/selinux/refpolicy/active/file_contexts 2>&1")
      print("FC:\n" + out)
      status, out = machine.execute("restorecon -R -F -f /run/selinux/refpolicy/active/file_contexts /nix/store 2>&1")
      print("RESTORECON:\n" + out)
      status, out = machine.execute("getfattr -n security.selinux --only-values ${enforceLearnApp}/bin/enforce-learn 2>&1")
      print("BIN CONTEXT:\n" + out)
      status, out = machine.execute(
          "ls -l ${enforceLearnApp}/bin/enforce-learn 2>&1; "
          "echo readlink=$(readlink ${enforceLearnApp}/bin/enforce-learn 2>&1); "
          "getfattr -h -n security.selinux --only-values ${enforceLearnApp}/bin/enforce-learn 2>&1"
      )
      print("SYMLINK CHECK:\n" + out)
      machine.succeed(
          "getfattr -n security.selinux --only-values ${enforceLearnApp}/bin/enforce-learn | grep -q enforce_learn_exec_t"
      )
      machine.succeed("selinux-relabel")
      # Runtime SELinux tooling must work: the policy/contexts must be present
      machine.succeed("ls /etc/selinux/refpolicy/policy/ 2>&1")
      machine.succeed("sestatus 2>&1")
      machine.succeed("restorecon -R /etc 2>&1")


      # Create the files the confined app reads, and label them.
      machine.succeed("mkdir -p /var/lib/enforce_learn")
      machine.succeed("echo allowed-data > /var/lib/enforce_learn/allowed")
      machine.succeed("echo secret-data > /var/lib/enforce_learn/secret")
      machine.succeed("setfattr -n security.selinux -v system_u:object_r:enforce_learn_data_t /var/lib/enforce_learn/allowed")
      machine.succeed("setfattr -n security.selinux -v system_u:object_r:enforce_learn_secret_t /var/lib/enforce_learn/secret")

      # Executing the binary transitions us into enforce_learn_t via the type
      # transition. The app exits 0 iff it can read its own data and cannot read
      # the secret file (i.e. SELinux enforcement is actually denying the latter).
      out = machine.succeed(
          "${enforceLearnApp}/bin/enforce-learn; echo app_rc=$?"
      )
      with subtest("SELinux is enforcing"):
          machine.succeed("test \"$(getenforce)\" = Enforcing")

      with subtest("the app binary has the enforce_learn_exec_t context"):
          machine.succeed(
              "getfattr -n security.selinux --only-values ${enforceLearnApp}/bin/enforce-learn | grep -q 'enforce_learn_exec_t'"
          )

      with subtest("the confined app can read its own data"):
          machine.succeed("echo '%s' | grep -q allowed_readable=1" % out)

      with subtest("the confined app cannot read the secret file"):
          machine.succeed("echo '%s' | grep -q secret_readable=0" % out)
    '';
}
