{
  senix,
  runCommand,
  gcc,
  glibc,
  testers,
  ...
}:
let
  # A tiny static binary that tries to open the allowed data file and the secret
  # file. SELinux enforcement means the `enforce_learn_t` domain can open
  # `allowed` (enforce_learn_data_t) but `open` on `secret`
  # (enforce_learn_secret_t) is denied (no allow rule -> EACCES).
  enforceLearnApp =
    runCommand "enforce-learn"
      {
        nativeBuildInputs = [
          gcc
        ];
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
        gcc -static -L${glibc.static}/lib -o "$out/bin/enforce-learn" main.c
      '';
in
testers.runNixOSTest {
  name = "selinux-enforce";

  node.pkgsReadOnly = false;

  nodes.machine =
    { lib, pkgs, ... }:
    {

      imports = [
        senix
      ];
      boot.kernelPackages = pkgs.linuxPackages_testing;

      security.selinux = {
        enable = true;
        mode = "enforcing";
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
              type setfiles_t;
              class capability2 { mac_admin };
            }

            type enforce_learn_exec_t;
            application_executable_file(enforce_learn_exec_t)

            # Migrated from `selinux_tools` (which must not depend on this
            # test-only type): the relabel domain + the labeler need access to
            # the app binary's file type.
            allow setfiles_t enforce_learn_exec_t:file relabelto;

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
            allow enforce_learn_t initrc_t:fifo_file rw_fifo_file_perms;

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

            allow initrc_t self:capability2 mac_admin;
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

      # [senix] Post-boot PID 1 context (diagnostic; the init_t grant landed when
      # this shows init_t and the "Failed to transition" warning is absent).
      print("[senix] P1 ctx:", machine.succeed("cat /proc/1/attr/current; echo; readlink /proc/1/exe"))
      print("[senix] mountinfo:", machine.succeed("cat /proc/self/mountinfo"))

      machine.succeed(
          "getfattr -n security.selinux --only-values ${enforceLearnApp}/bin/enforce-learn | grep -q enforce_learn_exec_t"
      )
      # Runtime SELinux tooling must work: the policy/contexts must be present
      machine.succeed("ls /etc/selinux/targeted/policy/ 2>&1")
      machine.succeed("sestatus 2>&1")

      # Create the files the confined app reads, and label them.
      machine.succeed("mkdir -p /var/lib/enforce_learn")
      machine.succeed("echo allowed-data > /var/lib/enforce_learn/allowed")
      machine.succeed("echo secret-data > /var/lib/enforce_learn/secret")
      machine.succeed("setfattr -n security.selinux -v system_u:object_r:enforce_learn_data_t:s0 /var/lib/enforce_learn/allowed")
      machine.succeed("setfattr -n security.selinux -v system_u:object_r:enforce_learn_secret_t:s0 /var/lib/enforce_learn/secret")

      # Executing the binary transitions us into enforce_learn_t via the type
      # transition. The app exits 0 iff it can read its own data and cannot read
      # the secret file (i.e. SELinux enforcement is actually denying the latter).
      out = machine.succeed(
          "${enforceLearnApp}/bin/enforce-learn; echo app_rc=$?"
      )
      # The type_transition must actually confine the process: it runs in the
      # `enforce_learn_t` domain, not as the caller.
      machine.succeed("echo '%s' | grep -q 'domain=system_u:system_r:enforce_learn_t'" % out)
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
