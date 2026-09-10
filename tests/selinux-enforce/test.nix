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

      # `runNixOSTest` drives the machine with a pre-built read-only `pkgs`, so we
      # must not try to apply the SELinux package overrides from the module.
      nixpkgs.overlays = lib.mkForce [ ];

      # `runNixOSTest` disables the module's overlay, so build systemd with
      # SELinux support directly (so it mounts selinuxfs and loads the policy).
      systemd.package = pkgs.systemd.override {
        withSelinux = true;
      };

      security.selinux = {
        enable = true;
        mode = "permissive";

        modules.enforce_learn = {
          typeEnforcement = ''
            policy_module(enforce_learn)

            require {
              type init_t;
              type kernel_t;
              type unconfined_t;
              type tty_device_t;
              type var_t;
              type var_lib_t;
              type unlabeled_t;
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
            allow kernel_t enforce_learn_t:process transition;
            type_transition kernel_t enforce_learn_exec_t:process enforce_learn_t;
            allow kernel_t enforce_learn_exec_t:file execute;

            type enforce_learn_data_t;
            files_type(enforce_learn_data_t)

            type enforce_learn_secret_t;
            # The app handles the stdio it inherited from the caller (the test
            # driver's shell, which is `kernel_t`) and the console it is bound
            # to; without these it cannot even print to stdout.
            allow enforce_learn_t kernel_t:fd use;
            allow enforce_learn_t unconfined_t:fd use;
            allow enforce_learn_t init_t:fd use;
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
      ];
    };

  testScript =
    # python
    ''
      machine.wait_for_unit("multi-user.target")

      # Create the files the confined app reads, and label them.
      machine.succeed("mkdir -p /var/lib/enforce_learn")
      machine.succeed("echo allowed-data > /var/lib/enforce_learn/allowed")
      machine.succeed("echo secret-data > /var/lib/enforce_learn/secret")
      machine.succeed("setfattr -n security.selinux -v system_u:object_r:enforce_learn_data_t /var/lib/enforce_learn/allowed")
      machine.succeed("setfattr -n security.selinux -v system_u:object_r:enforce_learn_secret_t /var/lib/enforce_learn/secret")

      # Apply the squashfs-supplied store labels. The `selinux-store-overlay`
      # command (re)mounts the metadata image and copies the baked
      # `security.selinux` labels onto the overlaid store paths via metadata-only
      # copy-up; among them is the app binary's `enforce_learn_exec_t` label so
      # exec'ing it triggers the `kernel_t -> enforce_learn_t` transition.
      machine.succeed("echo stale > /run/selinux/store-overlay-squashfs")
      machine.succeed("selinux-store-overlay")

      # The system boots permissive; switch to enforcing for the actual check.
      machine.succeed("setenforce 1")

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
