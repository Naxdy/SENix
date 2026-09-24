{
  senix,
  testers,
  ...
}:
testers.runNixOSTest {
  name = "plasma-login";

  node.pkgsReadOnly = false;

  # The greeter is asserted through screen text (wait_for_text).
  enableOCR = true;

  nodes.machine =
    { pkgs, ... }:
    {
      imports = [
        senix
      ];

      security.selinux = {
        enable = true;
        # AVC triage for the graphical login path happens in a later pass.
        mode = "permissive";
        overlayPackages = false;
      };

      # The account the test logs in with, and the only one SDDM lists
      # (sddm is built with UID_MIN=1000, the nixbld users sit above
      # Users.MaximumUid).
      users.users.alice = {
        isNormalUser = true;
        description = "Alice Foobar";
        password = "foobar";
        uid = 1000;
      };

      # `services.xserver` stays enabled only so the Wayland session gets
      # Xwayland + the XKB data (plasma6 references services.xserver.xkb);
      # the actual session (and the SDDM greeter) are Wayland.
      services.xserver.enable = true;
      services.desktopManager.plasma6.enable = true;

      services.displayManager = {
        # "plasma" is the Wayland session (startplasma-wayland); the X11 one
        # is "plasmax11".
        defaultSession = "plasma";

        sddm.enable = true;
      };

      # Trim every optional Plasma app the flow does not need. Kept:
      #  - dolphin: the app the test launches;
      #  - kate, which ships bin/kwrite, for KWrite;
      #  - kwin-x11, the compositor of the plasmax11 session;
      #  - ktexteditor (kate's elevated-actions helper) plus the entries
      #    marked required by upstream (qttools/qdbus, kconfig, qtbase) --
      #    those are called by the session itself.
      environment.plasma6.excludePackages = with pkgs.kdePackages; [
        ark
        aurorae
        baloo-widgets
        dolphin-plugins
        elisa
        ffmpegthumbs
        gwenview
        konsole
        khelpcenter
        krdp
        okular
        plasma-browser-integration
        plasma-keyboard
        plasma-workspace-wallpapers
        qtvirtualkeyboard
        spectacle
        union
      ];

      # More non-core baggage installed by the plasma6 module defaults:
      # fwupd (which also pulls in Discover), the Orca screen reader and the
      # KDE PIM suite (akonadi/kdepim-runtime) are irrelevant to a login flow.
      services.fwupd.enable = false;
      services.orca.enable = false;
      programs.kde-pim.enable = false;

      virtualisation.memorySize = 4096;
      virtualisation.cores = 2;
    };

  testScript =
    { nodes, ... }:
    let
      user = nodes.machine.users.users.alice;
    in
    # python
    ''
      import datetime as dt

      start_all()

      # Everything here is Wayland, so there is no X server to probe: the
      # greeter and session are asserted through the QEMU framebuffer (OCR +
      # screenshot) and the session's Wayland socket / process tree. The KWin
      # compositor renders to the KMS/DRM output that QEMU's VGA exposes, so
      # screendump captures it.
      with subtest("greeter presents the login screen"):
          machine.wait_for_unit("display-manager.service", timeout=dt.timedelta(seconds=240))
          machine.wait_for_text("(?i)(password|alice|shut down|restart|sleep|plasma|other)", timeout=dt.timedelta(seconds=120))
          machine.screenshot("plasma-login-greeter")

      with subtest("log in on the display manager"):
          # The breeze theme preselects the only listed user, so the password
          # field has focus and this submits it.
          machine.send_chars("${user.password}\n")

      with subtest("the session comes up as alice"):
          machine.wait_for_file("/run/user/${toString user.uid}/wayland-0", timeout=dt.timedelta(seconds=300))
          machine.wait_until_succeeds("pgrep -u ${toString user.uid} plasmashell", timeout=dt.timedelta(seconds=300))
          machine.wait_until_succeeds("pgrep -u ${toString user.uid} kwin_wayland", timeout=dt.timedelta(seconds=300))

      with subtest("excluded packages really are gone"):
          machine.succeed("which dolphin kwrite")
          machine.fail("which elisa")
          machine.fail("which konsole")

      with subtest("dolphin starts"):
          machine.execute(
              "runuser -u ${user.name} -- env XDG_RUNTIME_DIR=/run/user/${toString user.uid} "
              + "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/${toString user.uid}/bus "
              + "WAYLAND_DISPLAY=wayland-0 KDE_FULL_SESSION=true dolphin >&2 &"
          )
          machine.wait_until_succeeds("pgrep -u ${toString user.uid} dolphin", timeout=dt.timedelta(seconds=300))
          # KWin draws the server-side title ("Home — Dolphin"); OCR it as
          # proof the window was actually mapped, not merely spawned.
          machine.wait_for_text("(?i)dolphin", timeout=dt.timedelta(seconds=300))
          machine.sleep(dt.timedelta(seconds=5))
          machine.screenshot("plasma-login-dolphin")

      # `poweroff` never completes after a live KDE session: systemd blocks on
      # stopping the user session (KWin/plasmashell/dolphin linger) around the
      # SDDM teardown, so the driver's `wait_for_shutdown()` would hang. The
      # assertions and screenshots above are the actual proof, so tell the VM
      # to exit immediately instead.
      machine.crash()
    '';
}