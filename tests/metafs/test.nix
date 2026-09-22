{ testers, metafs, ... }:
testers.runNixOSTest {
  name = "metafs";

  node.pkgsReadOnly = false;

  nodes.machine =
    { pkgs, ... }:
    {
      # Load the FUSE kernel module so /dev/fuse exists and the pass-through
      # filesystem can actually be mounted (as root, mount(2) succeeds).
      boot.kernelModules = [ "fuse" ];

      environment.systemPackages = [
        metafs
        pkgs.attr
        pkgs.fuse
      ];
    };

  testScript =
    # python
    ''
      import datetime as dt

      machine.wait_for_unit("multi-user.target")

      # Surface the kernel's FUSE passthrough path so the read EIO can be
      # attributed to the exact step (pr_debug -> console with printk raised).
      machine.succeed("mount -t debugfs debugfs /sys/kernel/debug")
      machine.succeed("echo 8 > /proc/sys/kernel/printk")
      for dd_query in [
          "file fs/fuse/passthrough.c +p",
          "file fs/fuse/backing.c +p",
          "file fs/fuse/file.c +p",
          "file fs/backing-file.c +p",
          "file fs/fuse/dir.c +p",
      ]:
          machine.succeed(f"echo '{dd_query}' > /sys/kernel/debug/dynamic_debug/control")


      src = "/tmp/metafs-src"
      mnt = "/tmp/metafs-mnt"

      with subtest("prepare a source tree and mount metafs over it"):
          machine.succeed(f"rm -rf {src} {mnt}")
          machine.succeed(f"mkdir -p {src}/sub {mnt}")
          machine.succeed(f"printf 'hello world\n' > {src}/hello.txt")
          machine.succeed(f": > {src}/empty")
          machine.succeed(f"printf 'nested' > {src}/sub/nested.txt")
          machine.succeed(f"ln -s hello.txt {src}/link")
          machine.succeed(f"head -c 1048576 /dev/urandom > {src}/big.bin")
          daemon = int(machine.succeed(f"metafs -f {src} {mnt} >/tmp/metafs.log 2>&1 & echo $!"))
          machine.wait_until_succeeds(
              f"grep -q {mnt} /proc/self/mounts",
              timeout=dt.timedelta(seconds=30),
          )

      with subtest("reads pass through to the underlying filesystem exactly"):
          machine.succeed(f'test "$(cat "{mnt}/hello.txt")" = "hello world"')
          machine.succeed(f'test "$(cat "{mnt}/sub/nested.txt")" = "nested"')
          machine.succeed(f'test "$(cat "{mnt}/link")" = "hello world"')
          machine.succeed(f'test -L "{mnt}/link" && test "$(readlink "{mnt}/link")" = "hello.txt"')
          machine.succeed(f'cmp "{src}/big.bin" "{mnt}/big.bin"')
          machine.succeed(f'test -z "$(cat "{mnt}/empty")"')
          machine.succeed(f'ls -a "{mnt}" >/dev/null && df "{mnt}" >/dev/null')

      with subtest("structural mutations pass through to the underlying filesystem"):
          # Create a file and a directory *through the overlay*; both must exist
          # on the real backing tree and be fully readable there.
          machine.succeed(f"echo through-overlay > {mnt}/fresh.txt")
          machine.succeed(f"mkdir {mnt}/newdir")
          machine.succeed(f"printf nested > {mnt}/newdir/entry.bin")
          machine.succeed(f'test "$(cat "{src}/newdir/entry.bin")" = "nested"')
          machine.succeed(f'cat "{src}/fresh.txt" | grep -q through-overlay')

          # Rename across the overlay lands on the backing filesystem.
          machine.succeed(f"mv {mnt}/fresh.txt {mnt}/renamed.txt")
          machine.succeed(f'test ! -e "{src}/fresh.txt"')
          machine.succeed(f'cat "{src}/renamed.txt" | grep -q through-overlay')

          # Unlink / rmdir remove the real backed entries.
          machine.succeed(f"rm {mnt}/renamed.txt")
          machine.succeed(f"rm {mnt}/newdir/entry.bin")
          machine.succeed(f"rmdir {mnt}/newdir")
          machine.succeed(f'test ! -e "{src}/renamed.txt"')
          machine.succeed(f'test ! -e "{src}/newdir"')

          # Symlinking through the overlay creates a real symlink on the backing.
          machine.succeed(f"ln -s hello.txt {mnt}/sl")
          machine.succeed(f'test -L "{src}/sl" && test "$(readlink "{src}/sl")" = "hello.txt"')
          machine.succeed(f'cat "{mnt}/sl" | grep -q "^hello world"')
          machine.succeed(f"rm {mnt}/sl")

          # In-place content writes are served by FUSE passthrough and land on
          # the backing file itself.
          machine.succeed(f"echo x >> {mnt}/hello.txt")
          machine.succeed(f'test "$(cat "{mnt}/hello.txt")" = "hello world\nx"')
          machine.succeed(f'test "$(cat "{src}/hello.txt")" = "hello world\nx"')

          # The overlay and the backing agree on the resulting entry count.
          machine.succeed(f'test "$(find "{src}" -mindepth 1 | wc -l)" = "$(find "{mnt}" -mindepth 1 | wc -l)"')

      with subtest("xattrs are kept in memory, never on the underlying files"):
          machine.succeed(f"setfattr -n user.color -v red {mnt}/hello.txt")
          machine.succeed(f'test "$(getfattr -n user.color --only-values "{mnt}/hello.txt")" = "red"')

          # SELinux-style labels are supported too.
          machine.succeed(f"setfattr -n security.selinux -v system_u:object_r:etc_t:s0 {mnt}/hello.txt")
          machine.succeed(
              f'test "$(getfattr -n security.selinux --only-values "{mnt}/hello.txt")"'
              f' = "system_u:object_r:etc_t:s0"'
          )

          # Attributes are isolated per inode, not per path.
          machine.succeed(f"setfattr -n user.color -v blue {mnt}/sub/nested.txt")
          machine.succeed(f'test "$(getfattr -n user.color --only-values "{mnt}/sub/nested.txt")" = "blue"')
          machine.succeed(f'test "$(getfattr -n user.color --only-values "{mnt}/hello.txt")" = "red"')

          # The source files must not have gained any xattr.
          machine.succeed(f'! getfattr -d "{src}/hello.txt" 2>/dev/null | grep -q "^user\\."')

          # Removal drops the attribute from the in-memory store.
          machine.succeed(f"setfattr -x user.color {mnt}/hello.txt")
          machine.fail(f"getfattr -n user.color {mnt}/hello.txt")
          machine.succeed(
              f'test "$(getfattr -n security.selinux --only-values "{mnt}/hello.txt")"'
              f' = "system_u:object_r:etc_t:s0"'
          )

      with subtest("cleanup: explicit unmount ends the overlay"):
          # Killing the daemon alone only aborts the FUSE connection and leaves
          # a stale (unreachable) mount in /proc/mounts; unmounting while the
          # daemon is alive is the clean teardown.
          machine.succeed(f"umount {mnt}")
          machine.succeed(f"kill {daemon} || true")

      with subtest("metafs can be mounted directly over its own source"):
          # The source and the mountpoint are the *same* directory. Backing
          # accesses must reach the real filesystem behind the overlay instead
          # of re-entering the FUSE mount that shadows the path.
          self_dir = "/tmp/metafs-self"

          machine.succeed(f"rm -rf {self_dir} && mkdir -p {self_dir}")
          machine.succeed(f"printf 'origin\\n' > {self_dir}/origin.txt")
          machine.succeed(f"mkdir {self_dir}/dir")
          machine.succeed(f"printf 'nested\\n' > {self_dir}/dir/nested.txt")

          self_daemon = int(
              machine.succeed(f"metafs -f {self_dir} {self_dir} >/tmp/metafs-self.log 2>&1 & echo $!")
          )
          machine.wait_until_succeeds(
              f"grep -q {self_dir} /proc/self/mounts",
              timeout=dt.timedelta(seconds=30),
          )

          # Reads still reach the backing tree through the self-mount.
          machine.succeed(f'test "$(cat "{self_dir}/origin.txt")" = "origin"')
          machine.succeed(f'test "$(cat "{self_dir}/dir/nested.txt")" = "nested"')

          # Writes pass through to the real directory behind the self-mount.
          machine.succeed(f"mkdir {self_dir}/newdir")
          machine.succeed(f"echo written > {self_dir}/newdir/new.txt")
          machine.succeed(f'test "$(cat "{self_dir}/newdir/new.txt")" = "written"')

          # Xattrs are still held in memory.
          machine.succeed(f"setfattr -n user.color -v green {self_dir}/origin.txt")
          machine.succeed(f'test "$(getfattr -n user.color --only-values "{self_dir}/origin.txt")" = "green"')

          # Tear down; the real directory is visible again with the mutations
          # written through the overlay (but no xattrs on it).
          machine.succeed(f"umount {self_dir}")
          machine.succeed(f"kill {self_daemon} || true")
          machine.succeed(f'test "$(cat "{self_dir}/origin.txt")" = "origin"')
          machine.succeed(f'test "$(cat "{self_dir}/newdir/new.txt")" = "written"')
          machine.succeed(f'test "$(find "{self_dir}" -mindepth 1 | wc -l)" -eq 5')
          machine.succeed(f'! getfattr -d "{self_dir}/origin.txt" 2>/dev/null | grep -q "user\\."')

      with subtest("the overlay can be mounted through mount(8)"):
          # `mount -t fuse.metafs` dispatches to the mount.fuse helper, which
          # runs `metafs <source> <mountpoint> -o <opts>`; metafs must accept
          # that argv, daemonize, and report readiness so mount(8) returns.
          m8_dir = "/tmp/metafs-mnt8"
          machine.succeed(f"rm -rf {m8_dir} && mkdir -p {m8_dir}")
          machine.succeed(f"printf 'via-mount\\n' > {m8_dir}/f.txt")
          machine.succeed(f"mount -t fuse.metafs {m8_dir} {m8_dir}", timeout=dt.timedelta(seconds=30))

          machine.succeed(f'test "$(cat "{m8_dir}/f.txt")" = "via-mount"')
          machine.succeed(f"echo via-o > {m8_dir}/new.txt")
          machine.succeed(f"setfattr -n user.color -v amber {m8_dir}/f.txt")
          machine.succeed(f'test "$(getfattr -n user.color --only-values "{m8_dir}/f.txt")" = "amber"')

          machine.succeed(f"umount {m8_dir}")
          machine.succeed(f'test "$(cat "{m8_dir}/f.txt")" = "via-mount"')
          machine.succeed(f'test "$(cat "{m8_dir}/new.txt")" = "via-o"')
    '';
}
