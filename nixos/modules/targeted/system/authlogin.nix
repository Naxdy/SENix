{ lib, ... }:
{
  config.security.selinux.modules.authlogin.typeEnforcement = lib.mkAfter ''
    # `unix_chkpwd` is run out of the metafs store, which is mounted
    # `nosuid,nodev`. On a mount that does not allow suid (`mnt_may_suid()`
    # false) and where the exec changes the process context, the kernel's
    # `check_nnp_nosuid()` asks for `process2 nosuid_transition` in addition
    # to the ordinary `process transition`. The reference policy's
    # `auth_domtrans_chk_passwd()` uses `domtrans_pattern()`, which grants
    # only the ordinary transition because it assumes a normal mount.
    #
    # `chkpwd_t` is an `application_domain_type`, so the blanket
    # `allow { init_t initrc_t } { daemon init_domain_type ... }:process2
    # { nnp_transition nosuid_transition }` in `init.te` does not reach it.
    #
    # Alternatives: adding `chkpwd_t` to the `daemon` attribute would make the
    # blanket apply, but the reference policy deliberately keeps chkpwd_t in
    # `application_domain_type`; the `nosuid_domtrans_pattern()` macro would
    # re-emit the ordinary transition already granted by the interface, so only
    # its process2 half is needed. refpolicy and Fedora both keep
    # `auth_domtrans_chk_passwd()` on `domtrans_pattern()` because their
    # distributions run it off a suid-capable root, not a `nosuid` mount.
    #
    # Fedora's `init_nosuid_domain()` is the interface for exactly this half;
    # it is exported from the matching `init` module (see `init.nix`). This
    # is the observed init_t → chkpwd_t transition's minimum; `nnp_transition`
    # is not needed because this exec is not under `no_new_privs`.
    init_nosuid_domain(chkpwd_t)
  '';
}
