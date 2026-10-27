//! Parse fixtures for every supported dialect.
//!
//! These assert observable structure of the parsed trees, not the plumbing that
//! produces them.

use std::str::FromStr;

use sepol2nix::cil::{AvRuleKind, CilFile, PermissionXKind, Statement};
use sepol2nix::file_context::{FileItem, FileTypeFlag, SectionItem};
use sepol2nix::interface::{InfoflowKind, MacroKind};
use sepol2nix::m4::{Item, M4File};
use sepol2nix::metadata::LayerMetadata;
use sepol2nix::policy::context::{ContextValue, FileContextValue};
use sepol2nix::policy::statement::{
    AvRuleKind as TeRuleKind, Declaration, MacroStatement, Statement as TeStatement, TransitionKind,
};
use sepol2nix::type_enforcement::TypeEnforcementFile;

fn te() -> TypeEnforcementFile {
    TypeEnforcementFile::from_str(include_str!("fixtures/module.te")).expect("fixture parses")
}

fn iface() -> sepol2nix::interface::InterfaceFile {
    sepol2nix::interface::InterfaceFile::from_str(include_str!("fixtures/module.if"))
        .expect("fixture parses")
}

fn fc() -> sepol2nix::file_context::FileContextFile {
    sepol2nix::file_context::FileContextFile::from_str(include_str!("fixtures/module.fc"))
        .expect("fixture parses")
}

fn cil() -> CilFile {
    CilFile::from_str(include_str!("fixtures/module.cil")).expect("fixture parses")
}

#[test]
fn te_module_declaration_and_statement_classes() {
    let file = te();
    let module = file.module.as_ref().expect("module declaration");
    assert_eq!(module.name.text(), "fixture");
    assert_eq!(module.version.as_ref().expect("version").text(), "1.2.3");

    let mut seen_rules = Vec::new();
    let mut seen_transitions = Vec::new();
    let mut seen_macros = Vec::new();
    for statement in file.statements.statements() {
        match statement {
            TeStatement::AvTab(rule) => seen_rules.push(rule.kind),
            TeStatement::Transition(rule) => seen_transitions.push(rule.kind),
            TeStatement::Macro(macro_statement) => seen_macros.push(macro_statement),
            _ => {}
        }
    }
    assert_eq!(seen_rules[1], TeRuleKind::AuditAllow);
    assert_eq!(seen_rules[2], TeRuleKind::DontAudit);
    assert_eq!(seen_rules[3], TeRuleKind::NeverAllow);
    assert_eq!(seen_transitions[0], TransitionKind::Transition);
    assert_eq!(seen_transitions[1], TransitionKind::Member);

    let transition = file
        .statements
        .statements()
        .iter()
        .find_map(|statement| match statement {
            TeStatement::Transition(rule) if rule.kind == TransitionKind::Transition => Some(rule),
            _ => None,
        })
        .expect("type transition");
    assert_eq!(
        transition.file_name.as_ref().expect("quoted name").text(),
        "helper"
    );

    assert!(
        seen_macros
            .iter()
            .any(|statement| matches!(statement, MacroStatement::GenBool(_)))
    );
    assert!(
        seen_macros
            .iter()
            .any(|statement| matches!(statement, MacroStatement::GenTunable(_)))
    );
    assert!(seen_macros.iter().any(
        |statement| matches!(statement, MacroStatement::Conditional(conditional)
            if conditional.symbol.text() == "enable_mls")
    ));
    assert!(seen_macros.iter().any(
        |statement| matches!(statement, MacroStatement::TunablePolicy(policy)
            if policy.otherwise.is_some())
    ));

    let declarations: Vec<_> = file
        .statements
        .statements()
        .iter()
        .filter_map(|statement| match statement {
            TeStatement::Declaration(declaration) => Some(declaration),
            _ => None,
        })
        .collect();
    assert!(
        declarations
            .iter()
            .any(|declaration| matches!(declaration, Declaration::TypeAlias(_)))
    );
    assert!(
        declarations
            .iter()
            .any(|declaration| matches!(declaration, Declaration::AttributeRole(_)))
    );
}

#[test]
fn te_require_block_declarations_are_typed() {
    let file = te();
    let require = file
        .statements
        .statements()
        .iter()
        .find_map(|statement| match statement {
            TeStatement::Macro(MacroStatement::GenRequire(block)) => Some(block),
            _ => None,
        })
        .expect("gen_require block");
    assert!(require.declarations.iter().any(|declaration| matches!(
        declaration,
        sepol2nix::policy::statement::RequireDecl::Class { class, .. }
            if class.text() == "file"
    )));
}

#[test]
fn if_header_and_macro_docs() {
    let file = iface();
    assert_eq!(
        file.docs.summary.joined(),
        "Fixture module exercising the interface grammar."
    );
    assert!(file.docs.required.is_some());
    assert_eq!(file.declarations.len(), 2);

    let interface = &file.declarations[0];
    assert_eq!(interface.kind, MacroKind::Interface);
    assert_eq!(interface.name.to_string(), "fixture_use");
    assert_eq!(interface.docs.params.len(), 2);
    assert_eq!(interface.docs.params[1].name.text(), "objectclass(es)");
    assert!(interface.docs.params[1].optional);
    assert!(interface.docs.params[1].unused);
    assert!(interface.docs.rolecap);
    assert_eq!(
        interface.docs.infoflow.expect("infoflow").flow,
        InfoflowKind::Read
    );
    assert!(interface.body.gen_require.is_some());

    let template = &file.declarations[1];
    assert_eq!(template.kind, MacroKind::Template);
    assert!(template.docs.rolebase);
}

#[test]
fn fc_rules_flags_contexts_and_conditionals() {
    let file = fc();
    let mut flags = Vec::new();
    let mut generated = 0;
    let mut none = 0;
    let mut conditionals = Vec::new();
    for item in file.items() {
        match item {
            FileItem::Section(section) => {
                for entry in &section.items {
                    if let SectionItem::Rule(rule) = entry {
                        if let Some(file_type) = &rule.file_type {
                            flags.extend_from_slice(file_type.flags());
                        }
                        match &rule.context {
                            FileContextValue::Generated(context) => {
                                generated += 1;
                                assert!(context.range.is_some());
                            }
                            FileContextValue::None => none += 1,
                            FileContextValue::Literal(_) => {}
                        }
                    }
                }
            }
            FileItem::Conditional(conditional) => conditionals.push(conditional.symbol.text()),
        }
    }
    assert!(flags.contains(&FileTypeFlag::Ordinary));
    assert!(flags.contains(&FileTypeFlag::Socket));
    assert!(generated > 0);
    assert!(none > 0);
    assert_eq!(conditionals, ["distro_redhat", "distro_suse"]);

    let home = file
        .items()
        .iter()
        .filter_map(|item| match item {
            FileItem::Section(section) => Some(section),
            FileItem::Conditional(_) => None,
        })
        .flat_map(|section| section.items.iter())
        .filter_map(|entry| match entry {
            SectionItem::Rule(rule) => Some(rule),
            SectionItem::Comment(_) => None,
        })
        .filter(|rule| rule.path.home_macro().is_some())
        .count();
    assert_eq!(home, 2);
}

#[test]
fn cil_statement_kinds() {
    let file = cil();
    let mut allowx = Vec::new();
    let mut filecons_without_context = 0;
    let mut inline_permissionx = 0;
    let mut class_permission_sets = 0;
    for statement in file.statements() {
        #[allow(clippy::match_same_arms)]
        match statement {
            Statement::AvRuleX { kind, .. } => {
                allowx.push(*kind);
            }
            Statement::AvRule {
                kind: AvRuleKind::Allow,
                ..
            } => {}
            Statement::FileCon { context: None, .. } => filecons_without_context += 1,
            Statement::PermissionX { permission, .. }
                if permission.kind == PermissionXKind::Ioctl =>
            {
                inline_permissionx += 1;
            }
            Statement::ClassPermissionSet {
                class_permissions, ..
            } => {
                assert_eq!(class_permissions.items().len(), 1);
                class_permission_sets += 1;
            }
            Statement::Macro { params, .. } => assert_eq!(params.len(), 2),
            Statement::Call { arguments, .. } => assert_eq!(arguments.len(), 2),
            _ => {}
        }
    }
    assert_eq!(allowx, [AvRuleKind::Allow, AvRuleKind::NeverAllow]);
    assert_eq!(filecons_without_context, 1);
    assert_eq!(inline_permissionx, 1);
    assert_eq!(class_permission_sets, 1);
}

#[test]
fn m4_changequote_and_bare_definition() {
    let file = M4File::from_str(include_str!("fixtures/module.spt")).expect("fixture parses");
    let definitions: Vec<_> = file
        .items()
        .iter()
        .filter_map(|item| match item {
            Item::Definition(definition) => Some(definition),
            _ => None,
        })
        .collect();
    assert!(
        definitions
            .iter()
            .any(|definition| definition.name.text() == "fixture_depth")
    );

    // `changequote` inside a definition body is a directive token, and both
    // delimiter pairs occur in the `build_option` body.
    let build_option = definitions
        .iter()
        .find(|definition| definition.name.text() == "build_option")
        .expect("build_option definition");
    let mut pairs = Vec::new();
    for tree in build_option.body.tokens() {
        if let sepol2nix::lexer::TokenTree::Leaf(token) = tree
            && token.kind == sepol2nix::lexer::TokenKind::ChangeQuote
        {
            pairs.push(token.text.clone());
        }
    }
    assert_eq!(pairs.len(), 6);
    assert!(
        pairs
            .iter()
            .all(|pair| pair.contains("[,]") || pair.contains("`,'"))
    );
}

#[test]
fn metadata_summary() {
    let metadata = LayerMetadata::from_str(include_str!("fixtures/metadata.xml")).expect("parses");
    assert_eq!(metadata.summary.joined(), "Fixture layer metadata.");
}

#[test]
fn te_context_values_accept_gen_context_and_literals() {
    let file = TypeEnforcementFile::from_str(
        "policy_module(x)\nsid kernel gen_context(system_u:system_r:kernel_t,mls_systemhigh)\nfs_use_xattr ext4 system_u:object_r:fs_t:s0-s0:c0.c10;\n",
    )
    .expect("parses");
    let contexts: Vec<_> = file
        .statements
        .statements()
        .iter()
        .filter_map(|statement| match statement {
            TeStatement::Context(statement) => Some(statement),
            _ => None,
        })
        .flat_map(|statement| match statement {
            sepol2nix::policy::statement::ContextStatement::InitialSidContext(declaration) => {
                vec![&declaration.context]
            }
            sepol2nix::policy::statement::ContextStatement::FsUse(declaration) => {
                vec![&declaration.context]
            }
            _ => Vec::new(),
        })
        .collect();
    assert!(matches!(contexts[0], ContextValue::Generated(_)));
    assert!(matches!(contexts[1], ContextValue::Literal(_)));
}

#[test]
fn malformed_sources_fail() {
    assert!(TypeEnforcementFile::from_str("policy_module(x)\nallow a b:file read\n").is_err());
    assert!(sepol2nix::file_context::FileContextFile::from_str("/x\t-z\t<<none>>").is_err());
    assert!(CilFile::from_str("(allowx a b)").is_err());
    assert!(sepol2nix::interface::InterfaceFile::from_str("interface(`x',``')").is_err());
}

/// Debug rendering with source spans blanked, so re-emitted trees compare
/// structurally.
fn normalized<T: std::fmt::Debug>(value: &T) -> String {
    let span = regex::Regex::new(r"Span \{ start: \d+, end: \d+, line: \d+, column: \d+ \}")
        .expect("valid regex");
    span.replace_all(&format!("{value:?}"), "Span").into_owned()
}

fn assert_structurally_equal<T: std::fmt::Debug>(first: &T, second: &T) {
    let left = normalized(first);
    let right = normalized(second);
    if left != right {
        let index = left
            .bytes()
            .zip(right.bytes())
            .position(|(a, b)| a != b)
            .unwrap_or_else(|| left.len().min(right.len()));
        let start = index.saturating_sub(160);
        let end = (index + 160).min(left.len().max(right.len()));
        panic!(
            "trees differ at byte {index}\nleft:  …{}\nright: …{}",
            left.get(start..end).unwrap_or(""),
            right.get(start..end).unwrap_or("")
        );
    }
}

#[test]
fn trees_re_emit_and_reparse() {
    let te_source = include_str!("fixtures/module.te");
    let te_first = TypeEnforcementFile::from_str(te_source).expect("parses");
    let te_second = TypeEnforcementFile::from_str(&te_first.to_string()).expect("reparses");
    assert_structurally_equal(&te_first, &te_second);

    let fc_source = include_str!("fixtures/module.fc");
    let fc_first = sepol2nix::file_context::FileContextFile::from_str(fc_source).expect("parses");
    let fc_second = sepol2nix::file_context::FileContextFile::from_str(&fc_first.to_string())
        .expect("reparses");
    assert_structurally_equal(&fc_first, &fc_second);

    let if_source = include_str!("fixtures/module.if");
    let if_first = sepol2nix::interface::InterfaceFile::from_str(if_source).expect("parses");
    let if_second =
        sepol2nix::interface::InterfaceFile::from_str(&if_first.to_string()).expect("reparses");
    assert_structurally_equal(&if_first, &if_second);

    let m4_source = include_str!("fixtures/module.spt");
    let m4_first = M4File::from_str(m4_source).expect("parses");
    let m4_second = M4File::from_str(&m4_first.to_string()).expect("reparses");
    assert_structurally_equal(&m4_first, &m4_second);
}
