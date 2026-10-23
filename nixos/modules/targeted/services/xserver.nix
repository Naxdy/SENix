{ config, lib, ... }: {
  # SDDM's greeter is Qt Quick / QML, so Qt 6's QV4 JavaScript engine compiles
  # QML functions into anonymous executable memory. `sddm-greeter-qt6` is
  # labeled `xdm_exec_t` (the reference policy's `/usr/bin/sddm-greeter(-qt6)?`
  # rule) and runs as `xdm_t`, which therefore asks for `execmem` on its own
  # process. The reference policy places exactly that grant under the
  # `xserver_gnome_xdm` tunable (`allow xdm_t self:process execmem`, default
  # off and still so in upstream `main`) — it names the tunable after
  # gnome-shell's gdm greeter, but the rule is the same one SDDM's Qt greeter
  # needs. Fedora takes the grant out of that tunable and instead allows
  # `xdm_t` execmem by default, with `deny_execmem` (default off) opting out
  # (`policy/modules/services/xserver.te` + `policy/global_tunables`).
  #
  # Enabling the existing tunable therefore grants the single permission the
  # greeter asks for, without a new module, type, or role. Alternative: a
  # bespoke `xdm`-module rule mirroring Fedora's default — same permission,
  # but carried outside the refpolicy module that owns `xdm_t`, and without
  # the tunable's opt-out.
  config.security.selinux.booleans.xserver_gnome_xdm = lib.mkDefault true;
}
