{ ... }: {
  # This NixOS module supplies `.fc` configs with FHS paths corrected to work with
  # the Nix store, while the `.te`/`.if` are left to the Reference Policy source.

  imports = [
    # Modules from the refpolicy, transcribed to Nix so that
    # they can be extended declaratively.
    ./base

    # Custom modules bespoke to SENix / NixOS.
    ./custom

    # Modifications (mostly `.fc` labeling relate) and additions to modules
    # in the refpolicy.
    ./targeted
  ];
}
