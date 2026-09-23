{ helpers }:
helpers.mkSenixAppModule {
  name = "pipewire";
  category = "services";
  rules = {
    # PipeWire daemon executable.
    "@pipewire@/bin/pipewire" = "-- gen_context(system_u:object_r:pipewire_exec_t,s0)";
  };
}
