{
  helpers,
}:
helpers.mkSenixAppModule {
  name = "thunderbird";
  category = "programs";
  rules = {
    "@thunderbird@/bin/thunderbird.*" = "-- gen_context(system_u:object_r:thunderbird_exec_t,s0)";
  };
}
