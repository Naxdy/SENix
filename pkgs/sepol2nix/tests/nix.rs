//! Nix expression rendering for the file dialects.

use std::str::FromStr;

use sepol2nix::file_context::FileContextFile;
use sepol2nix::interface::InterfaceFile;
use sepol2nix::nix::AsNixExpr;
use sepol2nix::type_enforcement::TypeEnforcementFile;

fn if_nix() -> String {
    InterfaceFile::from_str(include_str!("fixtures/module.if"))
        .expect("fixture parses")
        .to_nix_string()
        .expect("renders")
}

fn fc_nix() -> String {
    FileContextFile::from_str(include_str!("fixtures/module.fc"))
        .expect("fixture parses")
        .to_nix_string()
        .expect("renders")
}

fn te_nix() -> String {
    TypeEnforcementFile::from_str(include_str!("fixtures/module.te"))
        .expect("fixture parses")
        .to_nix_string()
        .expect("renders")
}

#[test]
fn interface_exports_follow_the_option_schema() {
    let nix = if_nix();
    assert!(nix.starts_with("{\n  summary = \"Fixture module"));
    assert!(nix.contains("required = ''\n"));
    assert!(nix.contains("exports = {"));
    assert!(nix.contains("\"fixture_use\" = {"));
    assert!(nix.contains("params = {"));
    assert!(nix.contains("\"\\$1\" = {"));
    assert!(nix.contains("name = \"objectclass(es)\";"));
    assert!(nix.contains("optional = true;"));
    assert!(nix.contains("unused = true;"));
    assert!(nix.contains("type = \"template\";"));
    // The reference generator merges the header docs into the first macro.
    assert!(nix.contains("Describes parameters with spaces and parentheses."));
    assert!(nix.contains("gen_require = ''"));
    assert!(nix.contains("content = ''"));
    assert!(nix.contains("allow ''$1 fixture_t:file read;"));
    assert!(nix.contains("infoflow = {"));
    assert!(nix.contains("rolecap = true;"));
    assert!(nix.contains("rolebase = true;"));
    assert!(nix.ends_with("}\n"));
}

#[test]
fn file_context_rules_are_transformed_and_conditionalised() {
    let nix = fc_nix();
    assert!(nix.contains("/etc(/.*)?\" = lib.mkDefault"));
    assert!(nix.contains("fixture\\\\.conf"));
    assert!(nix.contains("-s <<none>>"));
    assert!(nix.contains("HOME_ROOT/\\\\.fixture"));
    assert!(nix.contains("HOME_DIR/\\\\.fixture(/.*)?\" = lib.mkDefault \"<<none>>\""));
    // `/usr` rules are commented by default.
    assert!(nix.contains("# \"/usr/bin/fixture\""));
    assert!(!nix.contains("\"/nix/store/[^/]+/bin/fixture\" ="));
    // `distro_redhat` is inactive, `distro_suse` resolves to the else branch.
    assert!(nix.contains("/etc/suse-release"));
    assert!(!nix.contains("/etc/redhat-release"));
    assert!(nix.contains("# Fixture file contexts."));
}

#[test]
fn long_file_context_rule_wraps_like_nixfmt() {
    let path = format!("/etc/{}/fixture.conf", "x".repeat(60));
    let source = format!("{path}\t--\tgen_context(system_u:object_r:fixture_etc_t,s0)\n");
    let file = FileContextFile::from_str(&source).expect("parses");
    let mut out = String::new();
    let empty = sepol2nix::nix::FileContextOptions::default();
    let mut nix = sepol2nix::nix::NixWriter::new(&mut out);
    file.write_nix_with_options(&mut nix, &empty)
        .expect("renders");
    assert!(out.contains(" =\n    lib.mkDefault \"-- gen_context"));
}

#[test]
fn type_enforcement_keeps_build_conditionals_and_drops_distro_blocks() {
    let nix = te_nix();
    assert!(nix.starts_with("''"));
    assert!(nix.contains("ifdef(`enable_mls',`"));
    assert!(nix.contains("attribute fixture_mls_type;"));
    assert!(nix.contains("ifndef(`enable_mcs',`"));
    assert!(nix.contains("allow fixture_t fixture_exec_t:file getattr;"));
    assert!(nix.contains("optional_policy(`"));
    assert!(nix.contains("tunable_policy(`fixture_tunable && !fixture_bool',`"));
    assert!(
        nix.contains("allowxperm fixture_t fixture_exec_t:file ioctl { 0x5401 0x5402-0x5404 };")
    );
    // The dead tail of the `dnl` line is not re-emitted as statements.
    assert!(!nix.contains("\n  a\n"));
}

#[test]
fn fixture_expressions_evaluate_with_a_stub_lib() {
    // Every fixture must be valid Nix; the wrapper only stubs `lib`.
    for expression in [if_nix(), fc_nix(), te_nix()] {
        let wrapped =
            format!("let lib = {{ mkDefault = x: x; mkBefore = x: x; }}; in\n{expression}");
        let path = std::env::temp_dir().join(format!("sepol2nix-eval-{}.nix", expression.len()));
        std::fs::write(&path, wrapped).expect("writes");
        let output = match std::process::Command::new("nix-instantiate")
            .args([
                "--store",
                "dummy://",
                "--eval",
                "--strict",
                "--json",
                &path.to_string_lossy(),
            ])
            .env(
                "NIX_STATE_DIR",
                std::env::temp_dir().join("sepol2nix-nix-state"),
            )
            .output()
        {
            Ok(output) => output,
            // The build sandbox has no Nix; the structural assertions above
            // still run there, evaluation needs a Nix-enabled host.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(error) => panic!("runs nix-instantiate: {error}"),
        };
        assert!(
            output.status.success(),
            "expression does not evaluate: {}\n{}",
            path.display(),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn substitute_usr_emits_commented_and_live_rules() {
    let file = FileContextFile::from_str(include_str!("fixtures/module.fc")).expect("parses");
    let render = |substitute_usr: Vec<sepol2nix::nix::UsrSubstitution>| {
        let mut out = String::new();
        let mut nix = sepol2nix::nix::NixWriter::new(&mut out);
        file.write_nix_with_options(
            &mut nix,
            &sepol2nix::nix::FileContextOptions { substitute_usr },
        )
        .expect("renders");
        out
    };

    let store = render(vec![sepol2nix::nix::UsrSubstitution::NixStore]);
    assert!(store.contains("# \"/usr/bin/fixture\""));
    assert!(store.contains("\"/nix/store/[^/]+/bin/fixture\" ="));
    assert!(store.contains("\"/nix/store/[^/]+/lib/fixture(/.*)?\" ="));
    assert!(!store.contains("@systemPath@"));

    let system = render(vec![sepol2nix::nix::UsrSubstitution::SystemPath]);
    assert!(system.contains("# \"/usr/bin/fixture\""));
    assert!(system.contains("\"@systemPath@/bin/fixture\" = lib.mkDefault"));
    assert!(!system.contains("/nix/store/[^/]+"));

    let both = render(vec![
        sepol2nix::nix::UsrSubstitution::NixStore,
        sepol2nix::nix::UsrSubstitution::SystemPath,
    ]);
    let commented = both.find("# \"/usr/bin/fixture\"").expect("commented");
    let store = both
        .find("\"/nix/store/[^/]+/bin/fixture\"")
        .expect("store");
    let system = both
        .find("\"@systemPath@/bin/fixture\"")
        .expect("system path");
    assert!(commented < store && store < system);
    // Non-`/usr` rules stay live.
    assert!(both.contains("\"/etc(/.*)?\" = lib.mkDefault"));
}

#[test]
fn m4_body_comments_keep_their_lines() {
    let source = "## <summary>Fixture</summary>\n\n########################################\n## <summary>X</summary>\ninterface(`x',`\n\tifelse(`a',`b',`dnl\n\t# why\n\tallow x y:z w;\n\t')\n')\n";
    let nix = InterfaceFile::from_str(source)
        .expect("parses")
        .to_nix_string()
        .expect("renders");
    assert!(nix.contains("# why\n        allow x y : z w ;"), "{nix}");
}
