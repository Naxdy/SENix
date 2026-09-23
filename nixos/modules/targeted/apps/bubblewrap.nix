{
  helpers,
}:
(helpers.mkSenixAppModule {
  name = "bubblewrap";
  addPackageOption = "bubblewrap";
  addEnableOption = true;
  category = "programs";
  rules = {
    "@bubblewrap@/bin/bwrap" = "--	gen_context(system_u:object_r:bubblewrap_exec_t,s0)";
  };
})
