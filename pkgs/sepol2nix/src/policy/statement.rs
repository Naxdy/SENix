//! The checkpolicy statement language, shared by `.te` files and `.if` macro
//! bodies.
//!
//! Statements are split into the grammar's own categories: declarations,
//! access-vector rules, transition rules, RBAC rules, conditional blocks,
//! `require`/`optional` blocks, context rules, constraint rules, and the `m4`
//! constructs the policy source is written in.
//!
//! Every rule and declaration carries its `;` terminator (`Semi`) so the trees
//! can be re-emitted verbatim.

use std::fmt;

use crate::error::{ParseError, ParseErrorKind, Result};
use crate::identifier::{
    AttributeId, BoolId, CategoryId, ClassId, Comment, CommonId, DeviceTreePath, DocComment,
    FileName, FilesystemId, GenfsFilesystem, GenfsPath, IbPkey, IbPort, Ident, Ioport, Ipv4Addr,
    Ipv4Cidr, Ipv6Addr, Ipv6Cidr, LevelId, ModuleName, NetifName, Number64, PciDevice, PermId,
    Pirq, PolicyCapId, RoleAttributeId, RoleId, SensitivityId, SidId, TunableId, TypeAliasId,
    TypeId, User, Version,
};
use crate::impl_from_str;
use crate::lexer::{Delimiter, TokenTree};
use crate::parser::{ParseFromTokens, Parser};
use crate::policy::context::ContextValue;
use crate::policy::expr::{BoolValue, CondExpr, ConstraintExpr};
use crate::policy::m4::{Conditional, Definition, Dnl, IfElse, MacroArg, MacroInvocation};
use crate::policy::mls::{CategorySet, MlsLevel, MlsRange};
use crate::policy::names::{IdCommaList, IdList, IdSet, NameSet};
use crate::policy::xperm::XPerms;

/// A statement terminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Semi(crate::span::Span);

impl ParseFromTokens for Semi {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        parser.expect_punct(';').map(Self)
    }
}

impl fmt::Display for Semi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(";")
    }
}

/// An inclusive numeric range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NumberRange<T> {
    /// The low bound.
    pub low: T,
    /// The high bound.
    pub high: T,
}

impl<T: ParseFromTokens + Copy> ParseFromTokens for NumberRange<T> {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        let low = T::parse_from_tokens(parser)?;
        let high = if parser.eat_punct('-') {
            T::parse_from_tokens(parser)?
        } else {
            low
        };
        Ok(Self { low, high })
    }
}

impl<T: fmt::Display> fmt::Display for NumberRange<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.low.to_string() == self.high.to_string() {
            fmt::Display::fmt(&self.low, f)
        } else {
            write!(f, "{}-{}", self.low, self.high)
        }
    }
}

/// The keyword of an access-vector rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AvRuleKind {
    /// `allow`
    Allow,
    /// `auditallow`
    AuditAllow,
    /// `auditdeny`
    AuditDeny,
    /// `dontaudit`
    DontAudit,
    /// `neverallow`
    NeverAllow,
}

impl AvRuleKind {
    /// The rule keyword.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::AuditAllow => "auditallow",
            Self::AuditDeny => "auditdeny",
            Self::DontAudit => "dontaudit",
            Self::NeverAllow => "neverallow",
        }
    }
}

impl fmt::Display for AvRuleKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The keyword of an extended-permission rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XPermRuleKind {
    /// `allowxperm`
    Allow,
    /// `auditallowxperm`
    AuditAllow,
    /// `dontauditxperm`
    DontAudit,
    /// `neverallowxperm`
    NeverAllow,
}

impl XPermRuleKind {
    /// The rule keyword.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allowxperm",
            Self::AuditAllow => "auditallowxperm",
            Self::DontAudit => "dontauditxperm",
            Self::NeverAllow => "neverallowxperm",
        }
    }
}

impl fmt::Display for XPermRuleKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The keyword of a type transition rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransitionKind {
    /// `type_transition`
    Transition,
    /// `type_member`
    Member,
    /// `type_change`
    Change,
}

impl TransitionKind {
    /// The rule keyword.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Transition => "type_transition",
            Self::Member => "type_member",
            Self::Change => "type_change",
        }
    }
}

impl fmt::Display for TransitionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An access-vector rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvTabRule {
    /// The rule keyword.
    pub kind: AvRuleKind,
    /// The source type set.
    pub source: NameSet<TypeId>,
    /// The target type set.
    pub target: NameSet<TypeId>,
    /// The object class set.
    pub classes: NameSet<ClassId>,
    /// The permission set.
    pub permissions: NameSet<PermId>,
    /// The terminator.
    pub terminator: Semi,
}

impl ParseFromTokens for AvTabRule {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        let kind = match parser.next_ident_text("an access-vector rule keyword")? {
            "allow" => AvRuleKind::Allow,
            "auditallow" => AvRuleKind::AuditAllow,
            "auditdeny" => AvRuleKind::AuditDeny,
            "dontaudit" => AvRuleKind::DontAudit,
            "neverallow" => AvRuleKind::NeverAllow,
            other => {
                return Err(ParseError::invalid(format!(
                    "not an access-vector rule: {other}"
                )));
            }
        };
        let source = NameSet::parse_from_tokens(parser)?;
        let target = NameSet::parse_from_tokens(parser)?;
        parser.expect_punct(':')?;
        let classes = NameSet::parse_from_tokens(parser)?;
        let permissions = NameSet::parse_from_tokens(parser)?;
        let terminator = Semi::parse_from_tokens(parser)?;
        Ok(Self {
            kind,
            source,
            target,
            classes,
            permissions,
            terminator,
        })
    }
}

impl fmt::Display for AvTabRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "{} {} {}:{} {};",
            self.kind, self.source, self.target, self.classes, self.permissions
        )
    }
}

/// An extended-permission rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XPermRule {
    /// The rule keyword.
    pub kind: XPermRuleKind,
    /// The source type set.
    pub source: NameSet<TypeId>,
    /// The target type set.
    pub target: NameSet<TypeId>,
    /// The object class set.
    pub classes: NameSet<ClassId>,
    /// The object permission the extended permissions belong to (`ioctl`, …).
    pub permission: PermId,
    /// The extended permissions.
    pub permissions: XPerms,
    /// The terminator.
    pub terminator: Semi,
}

impl ParseFromTokens for XPermRule {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        let kind = match parser.next_ident_text("an extended-permission rule keyword")? {
            "allowxperm" => XPermRuleKind::Allow,
            "auditallowxperm" => XPermRuleKind::AuditAllow,
            "dontauditxperm" => XPermRuleKind::DontAudit,
            "neverallowxperm" => XPermRuleKind::NeverAllow,
            other => {
                return Err(ParseError::invalid(format!(
                    "not an extended-permission rule: {other}"
                )));
            }
        };
        let source = NameSet::parse_from_tokens(parser)?;
        let target = NameSet::parse_from_tokens(parser)?;
        parser.expect_punct(':')?;
        let classes = NameSet::parse_from_tokens(parser)?;
        let permission = parser.parse_ident("an object permission")?;
        let permissions = XPerms::parse_from_tokens(parser)?;
        let terminator = Semi::parse_from_tokens(parser)?;
        Ok(Self {
            kind,
            source,
            target,
            classes,
            permission,
            permissions,
            terminator,
        })
    }
}

impl fmt::Display for XPermRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "{} {} {}:{} {} {};",
            self.kind, self.source, self.target, self.classes, self.permission, self.permissions
        )
    }
}

/// A type transition, member or change rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionRule {
    /// The rule keyword.
    pub kind: TransitionKind,
    /// The source type set.
    pub source: NameSet<TypeId>,
    /// The target type set.
    pub target: NameSet<TypeId>,
    /// The object class set.
    pub classes: NameSet<ClassId>,
    /// The resulting type.
    pub result: TypeId,
    /// The quoted file name that narrows the rule, if any.
    pub file_name: Option<FileName>,
    /// The terminator.
    pub terminator: Semi,
}

impl ParseFromTokens for TransitionRule {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        let kind = match parser.next_ident_text("a type rule keyword")? {
            "type_transition" => TransitionKind::Transition,
            "type_member" => TransitionKind::Member,
            "type_change" => TransitionKind::Change,
            other => return Err(ParseError::invalid(format!("not a type rule: {other}"))),
        };
        let source = NameSet::parse_from_tokens(parser)?;
        let target = NameSet::parse_from_tokens(parser)?;
        parser.expect_punct(':')?;
        let classes = NameSet::parse_from_tokens(parser)?;
        let result = parser.parse_ident("the resulting type")?;
        let file_name = parse_optional_filename(parser)?;
        let terminator = Semi::parse_from_tokens(parser)?;
        Ok(Self {
            kind,
            source,
            target,
            classes,
            result,
            file_name,
            terminator,
        })
    }
}

impl fmt::Display for TransitionRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {}:{} {}",
            self.kind, self.source, self.target, self.classes, self.result
        )?;
        if let Some(name) = &self.file_name {
            write!(f, " {name}")?;
        }
        writeln!(f, ";")
    }
}

/// A range transition rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeTransitionRule {
    /// The source type set.
    pub source: NameSet<TypeId>,
    /// The target type set.
    pub target: NameSet<TypeId>,
    /// The object class set narrowing the rule, if any.
    pub classes: Option<NameSet<ClassId>>,
    /// The resulting range.
    pub range: MlsRange,
    /// The terminator.
    pub terminator: Semi,
}

impl ParseFromTokens for RangeTransitionRule {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        parser.expect_keyword("range_transition")?;
        let source = NameSet::parse_from_tokens(parser)?;
        let target = NameSet::parse_from_tokens(parser)?;
        let classes = if parser.eat_punct(':') {
            Some(NameSet::parse_from_tokens(parser)?)
        } else {
            None
        };
        let range = MlsRange::parse_from_tokens(parser)?;
        let terminator = Semi::parse_from_tokens(parser)?;
        Ok(Self {
            source,
            target,
            classes,
            range,
            terminator,
        })
    }
}

/// A role transition rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleTransitionRule {
    /// The source role set.
    pub source: NameSet<RoleId>,
    /// The target role set.
    pub target: NameSet<RoleId>,
    /// The object class set narrowing the rule, if any.
    pub classes: Option<NameSet<ClassId>>,
    /// The resulting role.
    pub result: RoleId,
    /// The terminator.
    pub terminator: Semi,
}

impl ParseFromTokens for RoleTransitionRule {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        parser.expect_keyword("role_transition")?;
        let source = NameSet::parse_from_tokens(parser)?;
        let target = NameSet::parse_from_tokens(parser)?;
        let classes = if parser.eat_punct(':') {
            Some(NameSet::parse_from_tokens(parser)?)
        } else {
            None
        };
        let result = parser.parse_ident("the resulting role")?;
        let terminator = Semi::parse_from_tokens(parser)?;
        Ok(Self {
            source,
            target,
            classes,
            result,
            terminator,
        })
    }
}

/// A role-allow rule (`allow` between two role sets, without a class).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleAllowRule {
    /// The source role set.
    pub source: NameSet<RoleId>,
    /// The target role set.
    pub target: NameSet<RoleId>,
    /// The terminator.
    pub terminator: Semi,
}

impl fmt::Display for RoleAllowRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "allow {} {};", self.source, self.target)
    }
}

/// A declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Declaration {
    /// `attribute`
    Attribute(AttributeDecl),
    /// `expandattribute`
    ExpandAttribute(ExpandAttributeDecl),
    /// `type`
    Type(TypeDecl),
    /// `typealias`
    TypeAlias(TypeAliasDecl),
    /// `typeattribute`
    TypeAttribute(TypeAttributeDecl),
    /// `typebounds`
    TypeBounds(TypeBoundsDecl),
    /// `attribute_role`
    AttributeRole(AttributeRoleDecl),
    /// `role`
    Role(RoleDecl),
    /// `roleattribute`
    RoleAttribute(RoleAttributeDecl),
    /// `role <name> types …`
    RoleTypes(RoleTypesDecl),
    /// `bool`
    Bool(BoolDecl),
    /// `tunable`
    Tunable(TunableDecl),
    /// `permissive`
    Permissive(PermissiveDecl),
    /// `neveraudit`
    NeverAudit(NeverAuditDecl),
    /// `policycap`
    PolicyCap(PolicyCapDecl),
    /// `class`
    Class(ClassDecl),
    /// `class … { … }` or `class … inherits …`
    ClassPermissions(ClassPermissionsDecl),
    /// `common`
    Common(CommonDecl),
    /// `sid`
    InitialSid(InitialSidDecl),
    /// `default_user`
    DefaultUser(DefaultUserDecl),
    /// `default_role`
    DefaultRole(DefaultRoleDecl),
    /// `default_type`
    DefaultType(DefaultTypeDecl),
    /// `default_range`
    DefaultRange(DefaultRangeDecl),
    /// `sensitivity`
    Sensitivity(SensitivityDecl),
    /// `dominance`
    Dominance(DominanceDecl),
    /// `category`
    Category(CategoryDecl),
    /// `level`
    Level(LevelDecl),
    /// `user`
    User(UserDecl),
}

/// An `attribute` declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributeDecl {
    /// The attribute.
    pub attribute: AttributeId,
    /// The terminator.
    pub terminator: Semi,
}

/// An `expandattribute` declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpandAttributeDecl {
    /// The attributes.
    pub attributes: NameSet<AttributeId>,
    /// Whether to expand.
    pub expand: BoolValue,
    /// The terminator.
    pub terminator: Semi,
}

/// A `type` declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeDecl {
    /// The type.
    pub ty: TypeId,
    /// The optional `alias` name set.
    pub aliases: Option<NameSet<TypeAliasId>>,
    /// The attributes the type starts with.
    pub attributes: Option<IdCommaList<AttributeId>>,
    /// The terminator.
    pub terminator: Semi,
}

/// A `typealias` declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeAliasDecl {
    /// The type being aliased.
    pub ty: TypeId,
    /// The aliases.
    pub aliases: NameSet<TypeAliasId>,
    /// The terminator.
    pub terminator: Semi,
}

/// A `typeattribute` declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeAttributeDecl {
    /// The attribute.
    pub attribute: AttributeId,
    /// The types to attribute.
    pub types: IdCommaList<TypeId>,
    /// The terminator.
    pub terminator: Semi,
}

/// A `typebounds` declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeBoundsDecl {
    /// The bounded type.
    pub ty: TypeId,
    /// The bounding types.
    pub bounds: IdCommaList<TypeId>,
    /// The terminator.
    pub terminator: Semi,
}

/// An `attribute_role` declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributeRoleDecl {
    /// The role attribute.
    pub attribute: RoleAttributeId,
    /// The terminator.
    pub terminator: Semi,
}

/// A `role` declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleDecl {
    /// The role.
    pub role: RoleId,
    /// The role attributes the role starts with.
    pub attributes: Option<IdCommaList<RoleAttributeId>>,
    /// The terminator.
    pub terminator: Semi,
}

/// A `role <name> types …` declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleTypesDecl {
    /// The role.
    pub role: RoleId,
    /// The types the role is allowed to enter.
    pub types: NameSet<TypeId>,
    /// The terminator.
    pub terminator: Semi,
}

/// A `roleattribute` declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleAttributeDecl {
    /// The role attribute.
    pub attribute: RoleAttributeId,
    /// The roles to attribute.
    pub roles: IdCommaList<RoleId>,
    /// The terminator.
    pub terminator: Semi,
}

/// A `bool` declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoolDecl {
    /// The boolean.
    pub name: BoolId,
    /// Its default value.
    pub value: BoolValue,
    /// The terminator.
    pub terminator: Semi,
}

/// A `tunable` declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunableDecl {
    /// The tunable.
    pub name: TunableId,
    /// Its default value.
    pub value: BoolValue,
    /// The terminator.
    pub terminator: Semi,
}

/// A `permissive` declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissiveDecl {
    /// The type made permissive.
    pub ty: TypeId,
    /// The terminator.
    pub terminator: Semi,
}

/// A `neveraudit` declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeverAuditDecl {
    /// The type excluded from auditing.
    pub ty: TypeId,
    /// The terminator.
    pub terminator: Semi,
}

/// A `policycap` declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyCapDecl {
    /// The capability.
    pub capability: PolicyCapId,
    /// The terminator.
    pub terminator: Semi,
}

impl ParseFromTokens for PolicyCapDecl {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        parser.expect_keyword("policycap")?;
        Ok(Self {
            capability: parser.parse_ident("a policy capability")?,
            terminator: Semi::parse_from_tokens(parser)?,
        })
    }
}

/// A `class` declaration without permissions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassDecl {
    /// The class.
    pub class: ClassId,
    /// The optional terminator.
    pub terminator: Option<Semi>,
}

/// A `class … { … }` or `class … inherits …` declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassPermissionsDecl {
    /// The class.
    pub class: ClassId,
    /// The common permission set inherited from, if any.
    pub inherits: Option<CommonId>,
    /// The class's own permissions.
    pub permissions: Option<IdList<PermId>>,
    /// The optional terminator.
    pub terminator: Option<Semi>,
}

/// A `common` declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommonDecl {
    /// The common set.
    pub common: CommonId,
    /// Its permissions.
    pub permissions: IdList<PermId>,
    /// The optional terminator.
    pub terminator: Option<Semi>,
}

/// A `sid` declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitialSidDecl {
    /// The initial SID.
    pub sid: SidId,
    /// The optional terminator.
    pub terminator: Option<Semi>,
}

/// A `default_user` declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultUserDecl {
    /// The classes it applies to.
    pub classes: NameSet<ClassId>,
    /// Which side of the operation it applies to.
    pub target: DefaultTarget,
    /// The terminator.
    pub terminator: Semi,
}

/// A `default_role` declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultRoleDecl {
    /// The classes it applies to.
    pub classes: NameSet<ClassId>,
    /// Which side of the operation it applies to.
    pub target: DefaultTarget,
    /// The terminator.
    pub terminator: Semi,
}

/// A `default_type` declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultTypeDecl {
    /// The classes it applies to.
    pub classes: NameSet<ClassId>,
    /// Which side of the operation it applies to.
    pub target: DefaultTarget,
    /// The terminator.
    pub terminator: Semi,
}

/// A `default_range` declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultRangeDecl {
    /// The classes it applies to.
    pub classes: NameSet<ClassId>,
    /// Which side of the operation it applies to.
    pub target: DefaultRangeTarget,
    /// The terminator.
    pub terminator: Semi,
}

/// Which side of an operation a default rule applies to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DefaultRangeTarget {
    /// A source- or target-side range.
    Sided {
        /// The side.
        target: DefaultTarget,
        /// The range component.
        value: DefaultRangeValue,
    },
    /// `glblub`.
    Glblub,
}

/// A `sensitivity` declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensitivityDecl {
    /// The sensitivity.
    pub sensitivity: SensitivityId,
    /// Its aliases.
    pub aliases: Option<NameSet<SensitivityId>>,
    /// The terminator.
    pub terminator: Semi,
}

/// A `dominance` declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DominanceDecl {
    /// The dominated-over sensitivities.
    pub sensitivities: IdSet<SensitivityId>,
    /// The terminator.
    pub terminator: Semi,
}

/// A `category` declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CategoryDecl {
    /// The category.
    pub category: CategoryId,
    /// Its aliases.
    pub aliases: Option<NameSet<CategoryId>>,
    /// The terminator.
    pub terminator: Semi,
}

/// A `level` declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LevelDecl {
    /// The level name.
    pub level: LevelId,
    /// The categories it contains.
    pub categories: Option<CategorySet>,
    /// The terminator.
    pub terminator: Semi,
}

/// A `user` declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserDecl {
    /// The user.
    pub user: User,
    /// The roles reachable from the user.
    pub roles: NameSet<RoleId>,
    /// The user's default level.
    pub level: Option<MlsLevel>,
    /// The user's range.
    pub range: Option<MlsRange>,
    /// The terminator.
    pub terminator: Semi,
}

/// A context-bearing base statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextStatement {
    /// `sid <name> <context>`
    InitialSidContext(InitialSidContextDecl),
    /// `fs_use_xattr` / `fs_use_task` / `fs_use_trans`
    FsUse(FsUseDecl),
    /// `genfscon`
    GenfsCon(GenfsConDecl),
    /// `portcon`
    PortCon(PortConDecl),
    /// `netifcon`
    NetifCon(NetifConDecl),
    /// `nodecon`
    NodeCon(NodeConDecl),
    /// `pirqcon`
    PirqCon(PirqConDecl),
    /// `iomemcon`
    IomemCon(IomemConDecl),
    /// `ioportcon`
    IoportCon(IoportConDecl),
    /// `pcidevicecon`
    PciDeviceCon(PciDeviceConDecl),
    /// `devicetreecon`
    DeviceTreeCon(DeviceTreeConDecl),
    /// `ibpkeycon`
    IbPkeyCon(IbPkeyConDecl),
    /// `ibendportcon`
    IbEndPortCon(IbEndPortConDecl),
}

/// A `sid <name> <context>` statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitialSidContextDecl {
    /// The initial SID.
    pub sid: SidId,
    /// Its context.
    pub context: ContextValue,
    /// The optional terminator.
    pub terminator: Option<Semi>,
}

/// The flavor of an `fs_use_*` statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FsUseKind {
    /// `fs_use_xattr`
    Xattr,
    /// `fs_use_task`
    Task,
    /// `fs_use_trans`
    Trans,
}

impl FsUseKind {
    /// The statement keyword.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Xattr => "fs_use_xattr",
            Self::Task => "fs_use_task",
            Self::Trans => "fs_use_trans",
        }
    }
}

/// An `fs_use_*` statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsUseDecl {
    /// The flavor.
    pub kind: FsUseKind,
    /// The filesystem.
    pub filesystem: FilesystemId,
    /// The context used for its objects.
    pub context: ContextValue,
    /// The terminator.
    pub terminator: Semi,
}

/// The file-type marker of a `genfscon` statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenfsFileType {
    /// No type restriction (`--`).
    Any,
    /// A specific type restriction (`-d`).
    Kind(char),
}

/// A `genfscon` statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenfsConDecl {
    /// The filesystem.
    pub filesystem: GenfsFilesystem,
    /// The path within it.
    pub path: GenfsPath,
    /// The optional file-type marker.
    pub file_type: Option<GenfsFileType>,
    /// The context.
    pub context: ContextValue,
    /// The optional terminator.
    pub terminator: Option<Semi>,
}

/// A network protocol of a `portcon` statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PortProtocol {
    /// `tcp`
    Tcp,
    /// `udp`
    Udp,
    /// `dccp`
    Dccp,
    /// `sctp`
    Sctp,
}

impl PortProtocol {
    /// The protocol name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Dccp => "dccp",
            Self::Sctp => "sctp",
        }
    }
}

/// A `portcon` statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortConDecl {
    /// The protocol.
    pub protocol: PortProtocol,
    /// The port range.
    pub ports: NumberRange<crate::identifier::Port>,
    /// The context.
    pub context: ContextValue,
    /// The optional terminator.
    pub terminator: Option<Semi>,
}

/// A `netifcon` statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetifConDecl {
    /// The interface.
    pub interface: NetifName,
    /// The context of the interface itself.
    pub interface_context: ContextValue,
    /// The context of incoming packets.
    pub packet_context: ContextValue,
    /// The optional terminator.
    pub terminator: Option<Semi>,
}

/// The address operand of a `nodecon` statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeAddress {
    /// An IPv4 address and netmask.
    V4Pair(Ipv4Addr, Ipv4Addr),
    /// An IPv4 CIDR network.
    V4Cidr(Ipv4Cidr),
    /// An IPv6 address and netmask.
    V6Pair(Ipv6Addr, Ipv6Addr),
    /// An IPv6 CIDR network.
    V6Cidr(Ipv6Cidr),
}

/// A `nodecon` statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeConDecl {
    /// The address.
    pub address: NodeAddress,
    /// The context.
    pub context: ContextValue,
    /// The optional terminator.
    pub terminator: Option<Semi>,
}

/// A `pirqcon` statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PirqConDecl {
    /// The IRQ.
    pub irq: Pirq,
    /// The context.
    pub context: ContextValue,
    /// The optional terminator.
    pub terminator: Option<Semi>,
}

/// An `iomemcon` statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IomemConDecl {
    /// The memory range.
    pub memory: NumberRange<Number64>,
    /// The context.
    pub context: ContextValue,
    /// The optional terminator.
    pub terminator: Option<Semi>,
}

/// An `ioportcon` statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoportConDecl {
    /// The port range.
    pub ports: NumberRange<Ioport>,
    /// The context.
    pub context: ContextValue,
    /// The optional terminator.
    pub terminator: Option<Semi>,
}

/// A `pcidevicecon` statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PciDeviceConDecl {
    /// The device.
    pub device: PciDevice,
    /// The context.
    pub context: ContextValue,
    /// The optional terminator.
    pub terminator: Option<Semi>,
}

/// A `devicetreecon` statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceTreeConDecl {
    /// The device-tree path.
    pub path: DeviceTreePath,
    /// The context.
    pub context: ContextValue,
    /// The optional terminator.
    pub terminator: Option<Semi>,
}

/// An `ibpkeycon` statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IbPkeyConDecl {
    /// The subnet prefix.
    pub subnet: Ipv6Addr,
    /// The pkey range.
    pub pkeys: Option<NumberRange<IbPkey>>,
    /// The context.
    pub context: ContextValue,
    /// The optional terminator.
    pub terminator: Option<Semi>,
}

/// An `ibendportcon` statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IbEndPortConDecl {
    /// The device name.
    pub device: Ident,
    /// The end port.
    pub port: IbPort,
    /// The context.
    pub context: ContextValue,
    /// The optional terminator.
    pub terminator: Option<Semi>,
}

/// A constraint-bearing base statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConstraintStatement {
    /// `constrain`
    Constrain(ConstrainDecl),
    /// `mlsconstrain`
    MlsConstrain(ConstrainDecl),
    /// `validatetrans`
    ValidateTrans(ValidateTransDecl),
    /// `mlsvalidatetrans`
    MlsValidateTrans(ValidateTransDecl),
}

/// A `constrain` / `mlsconstrain` declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstrainDecl {
    /// The classes it applies to.
    pub classes: NameSet<ClassId>,
    /// The permissions it applies to.
    pub permissions: NameSet<PermId>,
    /// The constraint expression.
    pub expression: ConstraintExpr,
    /// The terminator.
    pub terminator: Semi,
}

/// A `validatetrans` / `mlsvalidatetrans` declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidateTransDecl {
    /// The classes it applies to.
    pub classes: NameSet<ClassId>,
    /// The constraint expression.
    pub expression: ConstraintExpr,
    /// The terminator.
    pub terminator: Semi,
}

/// A rule inside a conditional block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CondRule {
    /// A type rule.
    Transition(TransitionRule),
    /// An access-vector rule.
    AvTab(AvTabRule),
    /// An extended-permission rule.
    XPerm(XPermRule),
    /// A `require` block.
    Require(RequireBlock),
    /// A `#` comment line.
    Comment(Comment),
    /// A `##` documentation comment line.
    DocComment(DocComment),
    /// A macro construct.
    Macro(MacroStatement),
}

impl ParseFromTokens for CondRule {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        match parser.peek() {
            Some(TokenTree::Leaf(token)) if token.kind == crate::lexer::TokenKind::Comment => {
                let comment = Comment::new(token.text.clone());
                parser.next_tree();
                return Ok(Self::Comment(comment));
            }
            Some(TokenTree::Leaf(token)) if token.kind == crate::lexer::TokenKind::DocComment => {
                let comment = DocComment::new(token.text.clone());
                parser.next_tree();
                return Ok(Self::DocComment(comment));
            }
            Some(_) => {}
            None => {
                return Err(ParseError::at(
                    ParseErrorKind::UnexpectedEof {
                        expected: "a conditional rule",
                    },
                    parser.at(),
                ));
            }
        }
        let keyword = parser.peek_ident_text();
        match keyword {
            "type_transition" | "type_member" | "type_change" => {
                Ok(Self::Transition(TransitionRule::parse_from_tokens(parser)?))
            }
            "allow" | "auditallow" | "auditdeny" | "dontaudit" => {
                Ok(Self::AvTab(parse_av_tab(parser)?))
            }
            "allowxperm" | "auditallowxperm" | "dontauditxperm" => {
                Ok(Self::XPerm(XPermRule::parse_from_tokens(parser)?))
            }
            "require" => Ok(Self::Require(RequireBlock::parse_from_tokens(parser)?)),
            _ => Ok(Self::Macro(MacroStatement::parse_from_tokens(parser)?)),
        }
    }
}

/// Parses an access-vector rule without the role-allow alternative.
fn parse_av_tab(parser: &mut Parser<'_>) -> Result<AvTabRule> {
    let kind = match parser.next_ident_text("an access-vector rule keyword")? {
        "allow" => AvRuleKind::Allow,
        "auditallow" => AvRuleKind::AuditAllow,
        "auditdeny" => AvRuleKind::AuditDeny,
        "dontaudit" => AvRuleKind::DontAudit,
        other => {
            return Err(ParseError::invalid(format!(
                "not an access-vector rule: {other}"
            )));
        }
    };
    let source = NameSet::parse_from_tokens(parser)?;
    let target = NameSet::parse_from_tokens(parser)?;
    parser.expect_punct(':')?;
    let classes = NameSet::parse_from_tokens(parser)?;
    let permissions = NameSet::parse_from_tokens(parser)?;
    let terminator = Semi::parse_from_tokens(parser)?;
    Ok(AvTabRule {
        kind,
        source,
        target,
        classes,
        permissions,
        terminator,
    })
}

/// A list of conditional rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CondRuleList(Vec<CondRule>);

impl CondRuleList {
    /// The rules.
    #[must_use]
    pub fn rules(&self) -> &[CondRule] {
        &self.0
    }
}

impl ParseFromTokens for CondRuleList {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        let mut rules = Vec::new();
        while !parser.is_empty() {
            rules.push(CondRule::parse_from_tokens(parser)?);
        }
        Ok(Self(rules))
    }
}

/// An `if` conditional block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConditionalBlock {
    /// The condition.
    pub expression: CondExpr,
    /// The body taken when the condition holds.
    pub then: CondRuleList,
    /// The optional alternative body.
    pub otherwise: Option<CondRuleList>,
}

impl ParseFromTokens for ConditionalBlock {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        parser.expect_keyword("if")?;
        let expression = CondExpr::parse_from_tokens(parser)?;
        let then = CondRuleList::parse_from_tokens(&mut parser.next_brace("`{`")?)?;
        let otherwise = if parser.eat_keyword("else") {
            Some(CondRuleList::parse_from_tokens(
                &mut parser.next_brace("`{`")?,
            )?)
        } else {
            None
        };
        Ok(Self {
            expression,
            then,
            otherwise,
        })
    }
}

/// One declaration inside a `require` block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequireDecl {
    /// `class <name> <names>`
    Class {
        /// The class.
        class: ClassId,
        /// The required permissions.
        permissions: NameSet<PermId>,
        /// The terminator.
        terminator: Semi,
    },
    /// Required roles.
    Role(IdCommaList<RoleId>, Semi),
    /// Required types.
    Type(IdCommaList<TypeId>, Semi),
    /// Required attributes.
    Attribute(IdCommaList<AttributeId>, Semi),
    /// Required role attributes.
    AttributeRole(IdCommaList<RoleAttributeId>, Semi),
    /// Required users.
    User(IdCommaList<User>, Semi),
    /// Required booleans.
    Bool(IdCommaList<BoolId>, Semi),
    /// Required tunables.
    Tunable(IdCommaList<TunableId>, Semi),
    /// Required sensitivities.
    Sensitivity(IdCommaList<SensitivityId>, Semi),
    /// Required categories.
    Category(IdCommaList<CategoryId>, Semi),
}

impl ParseFromTokens for RequireDecl {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        let keyword = parser.next_ident_text("a required declaration")?;
        if keyword == "class" {
            let class = parser.parse_ident("a class")?;
            let permissions = NameSet::parse_from_tokens(parser)?;
            let terminator = Semi::parse_from_tokens(parser)?;
            return Ok(Self::Class {
                class,
                permissions,
                terminator,
            });
        }
        Ok(match keyword {
            "role" => Self::Role(
                IdCommaList::<RoleId>::parse_from_tokens(parser)?,
                Semi::parse_from_tokens(parser)?,
            ),
            "type" => Self::Type(
                IdCommaList::<TypeId>::parse_from_tokens(parser)?,
                Semi::parse_from_tokens(parser)?,
            ),
            "attribute" => Self::Attribute(
                IdCommaList::<AttributeId>::parse_from_tokens(parser)?,
                Semi::parse_from_tokens(parser)?,
            ),
            "attribute_role" => Self::AttributeRole(
                IdCommaList::<RoleAttributeId>::parse_from_tokens(parser)?,
                Semi::parse_from_tokens(parser)?,
            ),
            "user" => Self::User(
                IdCommaList::<User>::parse_from_tokens(parser)?,
                Semi::parse_from_tokens(parser)?,
            ),
            "bool" => Self::Bool(
                IdCommaList::<BoolId>::parse_from_tokens(parser)?,
                Semi::parse_from_tokens(parser)?,
            ),
            "tunable" => Self::Tunable(
                IdCommaList::<TunableId>::parse_from_tokens(parser)?,
                Semi::parse_from_tokens(parser)?,
            ),
            "sensitivity" => Self::Sensitivity(
                IdCommaList::<SensitivityId>::parse_from_tokens(parser)?,
                Semi::parse_from_tokens(parser)?,
            ),
            "category" => Self::Category(
                IdCommaList::<CategoryId>::parse_from_tokens(parser)?,
                Semi::parse_from_tokens(parser)?,
            ),
            other => {
                return Err(ParseError::invalid(format!(
                    "not a required declaration: {other}"
                )));
            }
        })
    }
}

/// A `require { … }` block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequireBlock {
    /// The required declarations.
    pub declarations: Vec<RequireDecl>,
}

impl ParseFromTokens for RequireBlock {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        parser.expect_keyword("require")?;
        let mut inner = parser.next_brace("`{`")?;
        let mut declarations = Vec::new();
        while let Some(tree) = inner.peek() {
            match tree {
                TokenTree::Leaf(token)
                    if matches!(
                        token.kind,
                        crate::lexer::TokenKind::Comment | crate::lexer::TokenKind::DocComment
                    ) =>
                {
                    inner.next_tree();
                }
                _ => declarations.push(RequireDecl::parse_from_tokens(&mut inner)?),
            }
        }
        Ok(Self { declarations })
    }
}

/// An `optional { … } [else { … }]` block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionalBlock {
    /// The optional body.
    pub body: StatementList,
    /// The alternative body.
    pub otherwise: Option<StatementList>,
}

impl ParseFromTokens for OptionalBlock {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        parser.expect_keyword("optional")?;
        let body = StatementList::parse_from_tokens(&mut parser.next_brace("`{`")?)?;
        let otherwise = if parser.eat_keyword("else") {
            Some(StatementList::parse_from_tokens(
                &mut parser.next_brace("`{`")?,
            )?)
        } else {
            None
        };
        Ok(Self { body, otherwise })
    }
}

/// A ``gen_require(`…')`` block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenRequireBlock {
    /// The required declarations.
    pub declarations: Vec<RequireDecl>,
}

impl ParseFromTokens for GenRequireBlock {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        parser.expect_keyword("gen_require")?;
        let mut args = parser.next_paren("the `gen_require` argument list")?;
        let mut declarations = Vec::new();
        if !args.is_empty() {
            let mut inner = args.next_quote_unwrapped("the quoted `gen_require` body")?;
            while let Some(tree) = inner.peek() {
                match tree {
                    TokenTree::Leaf(token)
                        if matches!(
                            token.kind,
                            crate::lexer::TokenKind::Comment | crate::lexer::TokenKind::DocComment
                        ) =>
                    {
                        inner.next_tree();
                    }
                    _ => declarations.push(RequireDecl::parse_from_tokens(&mut inner)?),
                }
            }
            inner.finish()?;
        }
        args.finish()?;
        Ok(Self { declarations })
    }
}

/// An ``optional_policy(`…')`` block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionalPolicyBlock {
    /// The body.
    pub body: StatementList,
}

impl ParseFromTokens for OptionalPolicyBlock {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        parser.expect_keyword("optional_policy")?;
        let mut inner = parser.next_paren("the `optional_policy` argument list")?;
        let mut body = inner.next_quote_unwrapped("the quoted policy body")?;
        let body = StatementList::parse_from_tokens(&mut body)?;
        inner.finish()?;
        Ok(Self { body })
    }
}

/// A `tunable_policy(<tunable>,`…'[,`…'])` block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunablePolicyBlock {
    /// The condition tested.
    pub condition: CondExpr,
    /// The body.
    pub body: StatementList,
    /// The optional alternative body.
    pub otherwise: Option<StatementList>,
}

impl ParseFromTokens for TunablePolicyBlock {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        parser.expect_keyword("tunable_policy")?;
        let mut inner = parser.next_paren("the `tunable_policy` argument list")?;
        let mut condition_parser = inner.next_quote_unwrapped("the quoted condition")?;
        let condition = CondExpr::parse_from_tokens(&mut condition_parser)?;
        condition_parser.finish()?;
        inner.expect_punct(',')?;
        let mut body = inner.next_quote_unwrapped("the quoted policy body")?;
        let body = StatementList::parse_from_tokens(&mut body)?;
        let otherwise = if inner.eat_punct(',') {
            let mut otherwise = inner.next_quote_unwrapped("the quoted alternative body")?;
            Some(StatementList::parse_from_tokens(&mut otherwise)?)
        } else {
            None
        };
        inner.finish()?;
        Ok(Self {
            condition,
            body,
            otherwise,
        })
    }
}

/// A `gen_bool(<name>,<default>)` declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenBoolDecl {
    /// The boolean.
    pub name: BoolId,
    /// Its default value.
    pub value: BoolValue,
}

impl ParseFromTokens for GenBoolDecl {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        parser.expect_keyword("gen_bool")?;
        let mut inner = parser.next_paren("the `gen_bool` argument list")?;
        let name = parse_argument_ident(&mut inner)?;
        inner.expect_punct(',')?;
        let value = parse_argument_bool(&mut inner)?;
        inner.finish()?;
        Ok(Self { name, value })
    }
}

/// A `gen_tunable(<name>,<default>)` declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenTunableDecl {
    /// The tunable.
    pub name: TunableId,
    /// Its default value.
    pub value: BoolValue,
}

impl ParseFromTokens for GenTunableDecl {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        parser.expect_keyword("gen_tunable")?;
        let mut inner = parser.next_paren("the `gen_tunable` argument list")?;
        let name = parse_argument_ident(&mut inner)?;
        inner.expect_punct(',')?;
        let value = parse_argument_bool(&mut inner)?;
        inner.finish()?;
        Ok(Self { name, value })
    }
}

/// A `policy_module(<name>[,<version>])` declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleDecl {
    /// The module name.
    pub name: ModuleName,
    /// The module version, if declared.
    pub version: Option<Version>,
}

impl ParseFromTokens for ModuleDecl {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        parser.expect_keyword("policy_module")?;
        let mut inner = parser.next_paren("the `policy_module` argument list")?;
        let name = parse_argument_ident(&mut inner)?;
        let version = if inner.eat_punct(',') {
            Some(parse_argument_version(&mut inner)?)
        } else {
            None
        };
        inner.finish()?;
        Ok(Self { name, version })
    }
}

/// Reads a one-token argument, quoted or bare.
fn parse_argument_ident<T: std::str::FromStr<Err = ParseError>>(
    parser: &mut Parser<'_>,
) -> Result<T> {
    if let Some(TokenTree::Group(group)) = parser.peek() {
        if group.delimiter == Delimiter::Quote {
            let mut inner = parser.next_quote("a quoted argument")?;
            let value = inner.parse_ident("an identifier")?;
            inner.finish()?;
            return Ok(value);
        }
    }
    parser.parse_ident("an argument")
}

fn parse_argument_bool(parser: &mut Parser<'_>) -> Result<BoolValue> {
    if let Some(TokenTree::Group(group)) = parser.peek() {
        if group.delimiter == Delimiter::Quote {
            let mut inner = parser.next_quote("a quoted argument")?;
            let value = BoolValue::parse_from_tokens(&mut inner)?;
            inner.finish()?;
            return Ok(value);
        }
    }
    BoolValue::parse_from_tokens(parser)
}

fn parse_argument_version(parser: &mut Parser<'_>) -> Result<Version> {
    if let Some(TokenTree::Group(group)) = parser.peek() {
        if group.delimiter == Delimiter::Quote {
            let mut inner = parser.next_quote("a quoted argument")?;
            let value = inner.parse_ident("a version")?;
            inner.finish()?;
            return Ok(value);
        }
    }
    parse_version_leaf(parser)
}

/// Reads a version token, which the scanner classifies as a [`Version`] leaf.
fn parse_version_leaf(parser: &mut Parser<'_>) -> Result<Version> {
    match parser.next_tree() {
        Some(TokenTree::Leaf(token)) => token.text.parse(),
        Some(tree) => Err(ParseError::unexpected(
            tree.describe(),
            "a version",
            tree.span(),
        )),
        None => Err(ParseError::at(
            ParseErrorKind::UnexpectedEof {
                expected: "a version",
            },
            parser.at(),
        )),
    }
}

/// A macro construct statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MacroStatement {
    /// `gen_require`
    GenRequire(GenRequireBlock),
    /// `optional_policy`
    OptionalPolicy(OptionalPolicyBlock),
    /// `tunable_policy`
    TunablePolicy(TunablePolicyBlock),
    /// `gen_bool`
    GenBool(GenBoolDecl),
    /// `gen_tunable`
    GenTunable(GenTunableDecl),
    /// `ifdef` / `ifndef`
    Conditional(Conditional<StatementList>),
    /// `ifelse`
    IfElse(IfElse),
    /// `define`
    Definition(Definition),
    /// `policy_module`
    Module(ModuleDecl),
    /// `dnl`
    Dnl(Dnl),
    /// Any other macro call.
    Invocation(MacroInvocation),
}

impl ParseFromTokens for MacroStatement {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        let keyword = parser.peek_ident_text();
        Ok(match keyword {
            "gen_require" => Self::GenRequire(GenRequireBlock::parse_from_tokens(parser)?),
            "optional_policy" => {
                Self::OptionalPolicy(OptionalPolicyBlock::parse_from_tokens(parser)?)
            }
            "tunable_policy" => Self::TunablePolicy(TunablePolicyBlock::parse_from_tokens(parser)?),
            "gen_bool" => Self::GenBool(GenBoolDecl::parse_from_tokens(parser)?),
            "gen_tunable" => Self::GenTunable(GenTunableDecl::parse_from_tokens(parser)?),
            "ifdef" | "ifndef" => Self::Conditional(parse_conditional(parser, keyword)?),
            "ifelse" => Self::IfElse(IfElse::parse_from_tokens(parser)?),
            "define" => Self::Definition(Definition::parse_from_tokens(parser)?),
            "policy_module" => Self::Module(ModuleDecl::parse_from_tokens(parser)?),
            "dnl" => {
                let line = parser
                    .peek()
                    .map_or(
                        crate::span::Span::start_of_source(),
                        crate::lexer::TokenTree::span,
                    )
                    .line;
                let dnl = Dnl::parse_from_tokens(parser)?;
                while let Some(tree) = parser.peek() {
                    if tree.span().line != line {
                        break;
                    }
                    parser.next_tree();
                }
                Self::Dnl(dnl)
            }
            other => {
                parser.next_tree();
                let name = other.parse()?;
                if parser.peek_paren() {
                    let mut inner = parser.next_paren("a macro argument list")?;
                    let args = if inner.is_empty() {
                        Vec::new()
                    } else {
                        let mut args = Vec::new();
                        loop {
                            args.push(MacroArg::parse_from_tokens(&mut inner)?);
                            if !inner.eat_punct(',') {
                                break;
                            }
                        }
                        args
                    };
                    inner.finish()?;
                    Self::Invocation(MacroInvocation {
                        name,
                        args: Some(args),
                    })
                } else {
                    Self::Invocation(MacroInvocation { name, args: None })
                }
            }
        })
    }
}

fn parse_conditional(parser: &mut Parser<'_>, keyword: &str) -> Result<Conditional<StatementList>> {
    parser.next_tree();
    let kind = if keyword == "ifdef" {
        crate::policy::m4::ConditionalKind::IfDef
    } else {
        crate::policy::m4::ConditionalKind::IfNDef
    };
    let mut args = parser.next_paren("the conditional argument list")?;
    let mut symbol_parser = args.next_quote("the quoted tested symbol")?;
    let symbol: crate::identifier::Symbol = symbol_parser.parse_ident("a condition symbol")?;
    symbol_parser.finish()?;
    args.expect_punct(',')?;
    let mut then_parser = args.next_quote_unwrapped("the quoted then-body")?;
    let then = StatementList::parse_from_tokens(&mut then_parser)?;
    let otherwise = if args.eat_punct(',') {
        let mut otherwise_parser = args.next_quote_unwrapped("the quoted else-body")?;
        let otherwise = StatementList::parse_from_tokens(&mut otherwise_parser)?;
        Some(otherwise)
    } else {
        None
    };
    args.finish()?;
    Ok(Conditional {
        kind,
        symbol,
        then,
        otherwise,
    })
}

/// A statement of the checkpolicy language.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Statement {
    /// A declaration.
    Declaration(Declaration),
    /// An access-vector rule.
    AvTab(AvTabRule),
    /// An extended-permission rule.
    XPerm(XPermRule),
    /// A type rule.
    Transition(TransitionRule),
    /// A range transition.
    RangeTransition(RangeTransitionRule),
    /// A role transition.
    RoleTransition(RoleTransitionRule),
    /// A role allow rule.
    RoleAllow(RoleAllowRule),
    /// An `if` block.
    Conditional(Box<ConditionalBlock>),
    /// A `require` block.
    Require(RequireBlock),
    /// An `optional` block.
    Optional(Box<OptionalBlock>),
    /// A `policycap` declaration.
    PolicyCap(PolicyCapDecl),
    /// A context statement.
    Context(ContextStatement),
    /// A constraint statement.
    Constraint(ConstraintStatement),
    /// A stray `;`.
    Empty(Semi),
    /// A `#` comment line.
    Comment(Comment),
    /// A `##` documentation comment line (consumed by the docs generator).
    DocComment(DocComment),
    /// A macro construct.
    Macro(MacroStatement),
}

impl ParseFromTokens for Statement {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        if let Some(TokenTree::Leaf(token)) = parser.peek() {
            if token.kind == crate::lexer::TokenKind::Punct(';') {
                return Ok(Self::Empty(Semi::parse_from_tokens(parser)?));
            }
        }
        match parser.peek() {
            Some(TokenTree::Leaf(token)) if token.kind == crate::lexer::TokenKind::Ident => {}
            Some(tree) => {
                return Err(ParseError::unexpected(
                    tree.describe(),
                    "a statement",
                    tree.span(),
                ));
            }
            None => {
                return Err(ParseError::at(
                    ParseErrorKind::UnexpectedEof {
                        expected: "a statement",
                    },
                    parser.at(),
                ));
            }
        }
        let keyword = parser.peek_ident_text();
        match keyword {
            "allow" | "auditallow" | "auditdeny" | "dontaudit" | "neverallow" => {
                Self::parse_av_rule(parser, keyword)
            }
            "allowxperm" | "auditallowxperm" | "dontauditxperm" | "neverallowxperm" => {
                Ok(Self::XPerm(XPermRule::parse_from_tokens(parser)?))
            }
            "type_transition" | "type_member" | "type_change" => {
                Ok(Self::Transition(TransitionRule::parse_from_tokens(parser)?))
            }
            "range_transition" => Ok(Self::RangeTransition(
                RangeTransitionRule::parse_from_tokens(parser)?,
            )),
            "role_transition" => Ok(Self::RoleTransition(RoleTransitionRule::parse_from_tokens(
                parser,
            )?)),
            "sid" => {
                parser.next_tree();
                let sid = parser.parse_ident("an initial SID")?;
                let looks_like_context = parser.peek_keyword("gen_context")
                    || (matches!(parser.peek(), Some(TokenTree::Leaf(token)) if token.kind == crate::lexer::TokenKind::Ident)
                        && matches!(parser.peek_second(), Some(TokenTree::Leaf(token)) if token.kind == crate::lexer::TokenKind::Punct(':')));
                if looks_like_context {
                    Ok(Self::Context(ContextStatement::InitialSidContext(
                        InitialSidContextDecl {
                            sid,
                            context: ContextValue::parse_from_tokens(parser)?,
                            terminator: optional_semi(parser)?,
                        },
                    )))
                } else {
                    Ok(Self::Declaration(Declaration::InitialSid(InitialSidDecl {
                        sid,
                        terminator: optional_semi(parser)?,
                    })))
                }
            }
            "attribute" | "attribute_role" | "bool" | "tunable" | "type" | "typealias"
            | "typeattribute" | "typebounds" | "expandattribute" | "role" | "roleattribute"
            | "permissive" | "neveraudit" | "class" | "common" | "default_user"
            | "default_role" | "default_type" | "default_range" | "sensitivity" | "dominance"
            | "category" | "level" | "user" => Ok(Self::Declaration(parse_declaration(parser)?)),
            "policycap" => Ok(Self::PolicyCap(PolicyCapDecl::parse_from_tokens(parser)?)),
            "constrain" | "mlsconstrain" | "validatetrans" | "mlsvalidatetrans" => {
                Ok(Self::Constraint(parse_constraint(parser, keyword)?))
            }
            "fs_use_xattr" | "fs_use_task" | "fs_use_trans" | "genfscon" | "portcon"
            | "netifcon" | "nodecon" | "pirqcon" | "iomemcon" | "ioportcon" | "pcidevicecon"
            | "devicetreecon" | "ibpkeycon" | "ibendportcon" => {
                Ok(Self::Context(parse_context(parser, keyword)?))
            }
            "if" => Ok(Self::Conditional(Box::new(
                ConditionalBlock::parse_from_tokens(parser)?,
            ))),
            "require" => Ok(Self::Require(RequireBlock::parse_from_tokens(parser)?)),
            "optional" => Ok(Self::Optional(Box::new(OptionalBlock::parse_from_tokens(
                parser,
            )?))),
            _ => Ok(Self::Macro(MacroStatement::parse_from_tokens(parser)?)),
        }
    }
}

impl Statement {
    fn parse_av_rule(parser: &mut Parser<'_>, keyword: &str) -> Result<Self> {
        let kind = match keyword {
            "allow" => AvRuleKind::Allow,
            "auditallow" => AvRuleKind::AuditAllow,
            "auditdeny" => AvRuleKind::AuditDeny,
            "dontaudit" => AvRuleKind::DontAudit,
            _ => AvRuleKind::NeverAllow,
        };
        parser.next_tree();
        let start = parser.position();
        let source = NameSet::parse_from_tokens(parser)?;
        let target = NameSet::parse_from_tokens(parser)?;
        if !parser.eat_punct(':') {
            if kind != AvRuleKind::Allow {
                return Err(ParseError::unexpected(
                    parser.peek().map_or_else(String::new, TokenTree::describe),
                    "`:`",
                    parser.at(),
                ));
            }
            parser.rewind(start);
            let source = NameSet::parse_from_tokens(parser)?;
            let target = NameSet::parse_from_tokens(parser)?;
            let terminator = Semi::parse_from_tokens(parser)?;
            return Ok(Self::RoleAllow(RoleAllowRule {
                source,
                target,
                terminator,
            }));
        }
        let classes = NameSet::parse_from_tokens(parser)?;
        let permissions = NameSet::parse_from_tokens(parser)?;
        let terminator = Semi::parse_from_tokens(parser)?;
        Ok(Self::AvTab(AvTabRule {
            kind,
            source,
            target,
            classes,
            permissions,
            terminator,
        }))
    }
}

/// Which side of an operation a `default_*` rule applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DefaultTarget {
    /// The source side.
    Source,
    /// The target side.
    Target,
}

impl ParseFromTokens for DefaultTarget {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        if parser.eat_keyword("source") {
            return Ok(Self::Source);
        }
        parser.expect_keyword("target")?;
        Ok(Self::Target)
    }
}

impl fmt::Display for DefaultTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Source => "source",
            Self::Target => "target",
        })
    }
}

/// The range component of a `default_range` rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DefaultRangeValue {
    /// `low`
    Low,
    /// `high`
    High,
    /// `low-high`
    LowHigh,
}

impl DefaultRangeValue {
    /// The value's source spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::High => "high",
            Self::LowHigh => "low-high",
        }
    }
}

impl fmt::Display for DefaultRangeValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

fn optional_semi(parser: &mut Parser<'_>) -> Result<Option<Semi>> {
    if parser.peek_punct(';') {
        Ok(Some(Semi::parse_from_tokens(parser)?))
    } else {
        Ok(None)
    }
}

fn parse_declaration(parser: &mut Parser<'_>) -> Result<Declaration> {
    let keyword = parser.next_ident_text("a declaration keyword")?;
    Ok(match keyword {
        "attribute" => Declaration::Attribute(AttributeDecl {
            attribute: parser.parse_ident("an attribute")?,
            terminator: Semi::parse_from_tokens(parser)?,
        }),
        "expandattribute" => Declaration::ExpandAttribute(ExpandAttributeDecl {
            attributes: NameSet::parse_from_tokens(parser)?,
            expand: BoolValue::parse_from_tokens(parser)?,
            terminator: Semi::parse_from_tokens(parser)?,
        }),
        "type" => {
            let ty = parser.parse_ident("a type")?;
            let aliases = if parser.eat_keyword("alias") {
                Some(NameSet::parse_from_tokens(parser)?)
            } else {
                None
            };
            let attributes = if parser.eat_punct(',') {
                Some(IdCommaList::parse_from_tokens(parser)?)
            } else {
                None
            };
            Declaration::Type(TypeDecl {
                ty,
                aliases,
                attributes,
                terminator: Semi::parse_from_tokens(parser)?,
            })
        }
        "typealias" => Declaration::TypeAlias(TypeAliasDecl {
            ty: parser.parse_ident("a type")?,
            aliases: {
                parser.expect_keyword("alias")?;
                NameSet::parse_from_tokens(parser)?
            },
            terminator: Semi::parse_from_tokens(parser)?,
        }),
        "typeattribute" => Declaration::TypeAttribute(TypeAttributeDecl {
            attribute: parser.parse_ident("an attribute")?,
            types: IdCommaList::parse_from_tokens(parser)?,
            terminator: Semi::parse_from_tokens(parser)?,
        }),
        "typebounds" => Declaration::TypeBounds(TypeBoundsDecl {
            ty: parser.parse_ident("a type")?,
            bounds: IdCommaList::parse_from_tokens(parser)?,
            terminator: Semi::parse_from_tokens(parser)?,
        }),
        "attribute_role" => Declaration::AttributeRole(AttributeRoleDecl {
            attribute: parser.parse_ident("a role attribute")?,
            terminator: Semi::parse_from_tokens(parser)?,
        }),
        "role" => {
            let role = parser.parse_ident("a role")?;
            if parser.eat_keyword("types") {
                return Ok(Declaration::RoleTypes(RoleTypesDecl {
                    role,
                    types: NameSet::parse_from_tokens(parser)?,
                    terminator: Semi::parse_from_tokens(parser)?,
                }));
            }
            let attributes = if parser.eat_punct(',') {
                Some(IdCommaList::parse_from_tokens(parser)?)
            } else {
                None
            };
            Declaration::Role(RoleDecl {
                role,
                attributes,
                terminator: Semi::parse_from_tokens(parser)?,
            })
        }
        "roleattribute" => Declaration::RoleAttribute(RoleAttributeDecl {
            attribute: parser.parse_ident("a role attribute")?,
            roles: IdCommaList::parse_from_tokens(parser)?,
            terminator: Semi::parse_from_tokens(parser)?,
        }),
        "bool" => Declaration::Bool(BoolDecl {
            name: parser.parse_ident("a boolean")?,
            value: BoolValue::parse_from_tokens(parser)?,
            terminator: Semi::parse_from_tokens(parser)?,
        }),
        "tunable" => Declaration::Tunable(TunableDecl {
            name: parser.parse_ident("a tunable")?,
            value: BoolValue::parse_from_tokens(parser)?,
            terminator: Semi::parse_from_tokens(parser)?,
        }),
        "permissive" => Declaration::Permissive(PermissiveDecl {
            ty: parser.parse_ident("a type")?,
            terminator: Semi::parse_from_tokens(parser)?,
        }),
        "neveraudit" => Declaration::NeverAudit(NeverAuditDecl {
            ty: parser.parse_ident("a type")?,
            terminator: Semi::parse_from_tokens(parser)?,
        }),
        "class" => {
            let class = parser.parse_ident("a class")?;
            let inherits = if parser.eat_keyword("inherits") {
                Some(parser.parse_ident("a common permission set")?)
            } else {
                None
            };
            let permissions = if parser.peek_brace() {
                Some(IdList::parse_from_tokens(&mut parser.next_brace("`{`")?)?)
            } else {
                None
            };
            if inherits.is_none() && permissions.is_none() {
                Declaration::Class(ClassDecl {
                    class,
                    terminator: optional_semi(parser)?,
                })
            } else {
                Declaration::ClassPermissions(ClassPermissionsDecl {
                    class,
                    inherits,
                    permissions,
                    terminator: optional_semi(parser)?,
                })
            }
        }
        "common" => Declaration::Common(CommonDecl {
            common: parser.parse_ident("a common permission set")?,
            permissions: IdList::parse_from_tokens(&mut parser.next_brace("`{`")?)?,
            terminator: optional_semi(parser)?,
        }),
        "sid" => Declaration::InitialSid(InitialSidDecl {
            sid: parser.parse_ident("an initial SID")?,
            terminator: optional_semi(parser)?,
        }),
        "default_user" | "default_role" | "default_type" => {
            let classes = NameSet::parse_from_tokens(parser)?;
            let target = DefaultTarget::parse_from_tokens(parser)?;
            let terminator = Semi::parse_from_tokens(parser)?;
            match keyword {
                "default_user" => Declaration::DefaultUser(DefaultUserDecl {
                    classes,
                    target,
                    terminator,
                }),
                "default_role" => Declaration::DefaultRole(DefaultRoleDecl {
                    classes,
                    target,
                    terminator,
                }),
                _ => Declaration::DefaultType(DefaultTypeDecl {
                    classes,
                    target,
                    terminator,
                }),
            }
        }
        "default_range" => {
            let classes = NameSet::parse_from_tokens(parser)?;
            let target = if parser.eat_keyword("glblub") {
                DefaultRangeTarget::Glblub
            } else {
                let target = DefaultTarget::parse_from_tokens(parser)?;
                let value = if parser.eat_keyword("low") {
                    DefaultRangeValue::Low
                } else if parser.eat_keyword("high") {
                    DefaultRangeValue::High
                } else {
                    parser.expect_keyword("low-high")?;
                    DefaultRangeValue::LowHigh
                };
                DefaultRangeTarget::Sided { target, value }
            };
            Declaration::DefaultRange(DefaultRangeDecl {
                classes,
                target,
                terminator: Semi::parse_from_tokens(parser)?,
            })
        }
        "sensitivity" => {
            let sensitivity = parser.parse_ident("a sensitivity")?;
            let aliases = if parser.eat_keyword("alias") {
                Some(NameSet::parse_from_tokens(parser)?)
            } else {
                None
            };
            Declaration::Sensitivity(SensitivityDecl {
                sensitivity,
                aliases,
                terminator: Semi::parse_from_tokens(parser)?,
            })
        }
        "dominance" => Declaration::Dominance(DominanceDecl {
            sensitivities: IdSet::parse_from_tokens(parser)?,
            terminator: Semi::parse_from_tokens(parser)?,
        }),
        "category" => {
            let category = parser.parse_ident("a category")?;
            let aliases = if parser.eat_keyword("alias") {
                Some(NameSet::parse_from_tokens(parser)?)
            } else {
                None
            };
            Declaration::Category(CategoryDecl {
                category,
                aliases,
                terminator: Semi::parse_from_tokens(parser)?,
            })
        }
        "level" => {
            let level = parser.parse_ident("a level")?;
            let categories = if parser.eat_punct(':') {
                Some(CategorySet::parse_from_tokens(parser)?)
            } else {
                None
            };
            Declaration::Level(LevelDecl {
                level,
                categories,
                terminator: Semi::parse_from_tokens(parser)?,
            })
        }
        "user" => {
            let user = parser.parse_ident("a user")?;
            parser.expect_keyword("roles")?;
            let roles = NameSet::parse_from_tokens(parser)?;
            let level = if parser.eat_keyword("level") {
                Some(MlsLevel::parse_from_tokens(parser)?)
            } else {
                None
            };
            let range = if parser.eat_keyword("range") {
                Some(MlsRange::parse_from_tokens(parser)?)
            } else {
                None
            };
            Declaration::User(UserDecl {
                user,
                roles,
                level,
                range,
                terminator: Semi::parse_from_tokens(parser)?,
            })
        }
        other => {
            return Err(ParseError::invalid(format!(
                "not a declaration keyword: {other}"
            )));
        }
    })
}

fn parse_constraint(parser: &mut Parser<'_>, keyword: &str) -> Result<ConstraintStatement> {
    parser.next_tree();
    let classes = NameSet::parse_from_tokens(parser)?;
    if keyword == "validatetrans" || keyword == "mlsvalidatetrans" {
        let mut expression = parser.next_paren("a constraint expression")?;
        let parsed = ConstraintExpr::parse_from_tokens(&mut expression)?;
        expression.finish()?;
        let terminator = Semi::parse_from_tokens(parser)?;
        let declaration = ValidateTransDecl {
            classes,
            expression: parsed,
            terminator,
        };
        return Ok(if keyword == "validatetrans" {
            ConstraintStatement::ValidateTrans(declaration)
        } else {
            ConstraintStatement::MlsValidateTrans(declaration)
        });
    }
    let permissions = NameSet::parse_from_tokens(parser)?;
    let mut expression = parser.next_paren("a constraint expression")?;
    let parsed = ConstraintExpr::parse_from_tokens(&mut expression)?;
    expression.finish()?;
    let terminator = Semi::parse_from_tokens(parser)?;
    let declaration = ConstrainDecl {
        classes,
        permissions,
        expression: parsed,
        terminator,
    };
    Ok(if keyword == "constrain" {
        ConstraintStatement::Constrain(declaration)
    } else {
        ConstraintStatement::MlsConstrain(declaration)
    })
}

fn parse_context(parser: &mut Parser<'_>, keyword: &str) -> Result<ContextStatement> {
    parser.next_tree();
    let optional_semi = |parser: &mut Parser<'_>| -> Result<Option<Semi>> {
        if parser.peek_punct(';') {
            Ok(Some(Semi::parse_from_tokens(parser)?))
        } else {
            Ok(None)
        }
    };
    Ok(match keyword {
        "fs_use_xattr" | "fs_use_task" | "fs_use_trans" => {
            let kind = match keyword {
                "fs_use_xattr" => FsUseKind::Xattr,
                "fs_use_task" => FsUseKind::Task,
                _ => FsUseKind::Trans,
            };
            ContextStatement::FsUse(FsUseDecl {
                kind,
                filesystem: parser.parse_ident("a filesystem")?,
                context: ContextValue::parse_from_tokens(parser)?,
                terminator: Semi::parse_from_tokens(parser)?,
            })
        }
        "genfscon" => {
            let filesystem = parser.parse_ident("a filesystem")?;
            let path = parse_path::<GenfsPath>(parser, "a genfs path")?;
            let file_type = if !parser.eat_punct('-') {
                None
            } else if parser.eat_punct('-') {
                Some(GenfsFileType::Any)
            } else {
                let text = parser.next_ident_text("a file type")?;
                let mut chars = text.chars();
                let (Some(kind), None) = (chars.next(), chars.next()) else {
                    return Err(ParseError::invalid(format!(
                        "genfscon file type must be one character: {text:?}"
                    )));
                };
                Some(GenfsFileType::Kind(kind))
            };
            ContextStatement::GenfsCon(GenfsConDecl {
                filesystem,
                path,
                file_type,
                context: ContextValue::parse_from_tokens(parser)?,
                terminator: if parser.peek_punct(';') {
                    Some(Semi::parse_from_tokens(parser)?)
                } else {
                    None
                },
            })
        }
        "portcon" => {
            let protocol = match parser.next_ident_text("a protocol")? {
                "tcp" => PortProtocol::Tcp,
                "udp" => PortProtocol::Udp,
                "dccp" => PortProtocol::Dccp,
                "sctp" => PortProtocol::Sctp,
                other => {
                    return Err(ParseError::invalid(format!("not a protocol: {other}")));
                }
            };
            ContextStatement::PortCon(PortConDecl {
                protocol,
                ports: NumberRange::parse_from_tokens(parser)?,
                context: ContextValue::parse_from_tokens(parser)?,
                terminator: optional_semi(parser)?,
            })
        }
        "netifcon" => ContextStatement::NetifCon(NetifConDecl {
            interface: parser.parse_ident("an interface")?,
            interface_context: ContextValue::parse_from_tokens(parser)?,
            packet_context: ContextValue::parse_from_tokens(parser)?,
            terminator: optional_semi(parser)?,
        }),
        "nodecon" => {
            let address = match parser.peek() {
                Some(TokenTree::Leaf(token)) if token.kind == crate::lexer::TokenKind::Ipv4Cidr => {
                    NodeAddress::V4Cidr(parser.parse_ident("an IPv4 network")?)
                }
                Some(TokenTree::Leaf(token)) if token.kind == crate::lexer::TokenKind::Ipv6Cidr => {
                    NodeAddress::V6Cidr(parser.parse_ident("an IPv6 network")?)
                }
                Some(TokenTree::Leaf(token)) if token.kind == crate::lexer::TokenKind::Ipv4Addr => {
                    NodeAddress::V4Pair(
                        parser.parse_ident("an IPv4 address")?,
                        parser.parse_ident("an IPv4 netmask")?,
                    )
                }
                Some(TokenTree::Leaf(token)) if token.kind == crate::lexer::TokenKind::Ipv6Addr => {
                    NodeAddress::V6Pair(
                        parser.parse_ident("an IPv6 address")?,
                        parser.parse_ident("an IPv6 netmask")?,
                    )
                }
                Some(tree) => {
                    return Err(ParseError::unexpected(
                        tree.describe(),
                        "an IP address",
                        tree.span(),
                    ));
                }
                None => {
                    return Err(ParseError::at(
                        ParseErrorKind::UnexpectedEof {
                            expected: "an IP address",
                        },
                        parser.at(),
                    ));
                }
            };
            ContextStatement::NodeCon(NodeConDecl {
                address,
                context: ContextValue::parse_from_tokens(parser)?,
                terminator: optional_semi(parser)?,
            })
        }
        "pirqcon" => ContextStatement::PirqCon(PirqConDecl {
            irq: parser.parse_ident("an IRQ")?,
            context: ContextValue::parse_from_tokens(parser)?,
            terminator: optional_semi(parser)?,
        }),
        "iomemcon" => ContextStatement::IomemCon(IomemConDecl {
            memory: NumberRange::parse_from_tokens(parser)?,
            context: ContextValue::parse_from_tokens(parser)?,
            terminator: optional_semi(parser)?,
        }),
        "ioportcon" => ContextStatement::IoportCon(IoportConDecl {
            ports: NumberRange::parse_from_tokens(parser)?,
            context: ContextValue::parse_from_tokens(parser)?,
            terminator: optional_semi(parser)?,
        }),
        "pcidevicecon" => ContextStatement::PciDeviceCon(PciDeviceConDecl {
            device: parser.parse_ident("a PCI device")?,
            context: ContextValue::parse_from_tokens(parser)?,
            terminator: optional_semi(parser)?,
        }),
        "devicetreecon" => ContextStatement::DeviceTreeCon(DeviceTreeConDecl {
            path: parse_path::<DeviceTreePath>(parser, "a device-tree path")?,
            context: ContextValue::parse_from_tokens(parser)?,
            terminator: optional_semi(parser)?,
        }),
        "ibpkeycon" => ContextStatement::IbPkeyCon(IbPkeyConDecl {
            subnet: parser.parse_ident("an IPv6 subnet prefix")?,
            pkeys: if parser.peek_punct('-') || is_number_start(parser) {
                Some(NumberRange::parse_from_tokens(parser)?)
            } else {
                None
            },
            context: ContextValue::parse_from_tokens(parser)?,
            terminator: optional_semi(parser)?,
        }),
        "ibendportcon" => ContextStatement::IbEndPortCon(IbEndPortConDecl {
            device: parser.parse_ident("a device name")?,
            port: parser.parse_ident("an end port")?,
            context: ContextValue::parse_from_tokens(parser)?,
            terminator: optional_semi(parser)?,
        }),
        other => {
            return Err(ParseError::invalid(format!(
                "not a context statement: {other}"
            )));
        }
    })
}

/// Reads a quoted file-name token, if one follows.
fn parse_optional_filename(parser: &mut Parser<'_>) -> Result<Option<FileName>> {
    match parser.peek() {
        Some(TokenTree::Leaf(token)) if token.kind == crate::lexer::TokenKind::Filename => {
            let name = token.text.parse()?;
            parser.next_tree();
            Ok(Some(name))
        }
        _ => Ok(None),
    }
}

/// Reads a path token, which the scanner classifies as a path leaf.
fn parse_path<T: std::str::FromStr<Err = ParseError>>(
    parser: &mut Parser<'_>,
    expected: &'static str,
) -> Result<T> {
    match parser.next_tree() {
        Some(TokenTree::Leaf(token))
            if matches!(
                token.kind,
                crate::lexer::TokenKind::Path | crate::lexer::TokenKind::QPath
            ) =>
        {
            token.text.parse()
        }
        Some(tree) => Err(ParseError::unexpected(
            tree.describe(),
            expected,
            tree.span(),
        )),
        None => Err(ParseError::at(
            ParseErrorKind::UnexpectedEof { expected },
            parser.at(),
        )),
    }
}

fn is_number_start(parser: &Parser<'_>) -> bool {
    matches!(
        parser.peek(),
        Some(TokenTree::Leaf(token)) if token.kind == crate::lexer::TokenKind::Number
    )
}

/// A list of statements.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StatementList(Vec<Statement>);

impl StatementList {
    /// Creates a list from parsed statements.
    #[must_use]
    pub fn new(statements: Vec<Statement>) -> Self {
        Self(statements)
    }

    /// The statements.
    #[must_use]
    pub fn statements(&self) -> &[Statement] {
        &self.0
    }
}

impl ParseFromTokens for StatementList {
    fn parse_from_tokens(parser: &mut Parser<'_>) -> Result<Self> {
        let mut statements = Vec::new();
        while let Some(tree) = parser.peek() {
            match tree {
                TokenTree::Leaf(token) if token.kind == crate::lexer::TokenKind::Comment => {
                    statements.push(Statement::Comment(Comment::new(token.text.clone())));
                    parser.next_tree();
                }
                TokenTree::Leaf(token) if token.kind == crate::lexer::TokenKind::DocComment => {
                    statements.push(Statement::DocComment(DocComment::new(token.text.clone())));
                    parser.next_tree();
                }
                _ => statements.push(Statement::parse_from_tokens(parser)?),
            }
        }
        Ok(Self(statements))
    }
}

impl_from_str!(StatementList);

impl fmt::Display for StatementList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for statement in &self.0 {
            write!(f, "{statement}")?;
        }
        Ok(())
    }
}

impl fmt::Display for Statement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Declaration(declaration) => fmt::Display::fmt(declaration, f),
            Self::AvTab(rule) => fmt::Display::fmt(rule, f),
            Self::XPerm(rule) => fmt::Display::fmt(rule, f),
            Self::Transition(rule) => fmt::Display::fmt(rule, f),
            Self::RangeTransition(rule) => fmt::Display::fmt(rule, f),
            Self::RoleTransition(rule) => fmt::Display::fmt(rule, f),
            Self::RoleAllow(rule) => fmt::Display::fmt(rule, f),
            Self::Conditional(block) => fmt::Display::fmt(block, f),
            Self::Require(block) => fmt::Display::fmt(block, f),
            Self::Optional(block) => fmt::Display::fmt(block, f),
            Self::PolicyCap(declaration) => fmt::Display::fmt(declaration, f),
            Self::Context(statement) => fmt::Display::fmt(statement, f),
            Self::Constraint(statement) => fmt::Display::fmt(statement, f),
            Self::Empty(semi) => writeln!(f, "{semi}"),
            Self::Comment(comment) => writeln!(f, "{comment}"),
            Self::DocComment(comment) => writeln!(f, "{comment}"),
            Self::Macro(statement) => fmt::Display::fmt(statement, f),
        }
    }
}

macro_rules! decl_display {
    ($ty:ty, $keyword:literal, |$self:ident, $f:ident| $body:expr) => {
        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let $self = self;
                let $f = &mut *f;
                $f.write_str($keyword)?;
                $f.write_str(" ")?;
                { $body }?;
                writeln!($f, ";")
            }
        }
    };
}

decl_display!(AttributeDecl, "attribute", |s, f| fmt::Display::fmt(
    &s.attribute,
    f
));
decl_display!(AttributeRoleDecl, "attribute_role", |s, f| {
    fmt::Display::fmt(&s.attribute, f)
});
impl fmt::Display for ClassDecl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "class {}", self.class)?;
        if self.terminator.is_some() {
            f.write_str(";")?;
        }
        writeln!(f)
    }
}
impl fmt::Display for InitialSidDecl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sid {}", self.sid)?;
        if self.terminator.is_some() {
            f.write_str(";")?;
        }
        writeln!(f)
    }
}
decl_display!(PermissiveDecl, "permissive", |s, f| fmt::Display::fmt(
    &s.ty, f
));
decl_display!(NeverAuditDecl, "neveraudit", |s, f| fmt::Display::fmt(
    &s.ty, f
));
decl_display!(PolicyCapDecl, "policycap", |s, f| fmt::Display::fmt(
    &s.capability,
    f
));
decl_display!(BoolDecl, "bool", |s, f| write!(f, "{} {}", s.name, s.value));
decl_display!(TunableDecl, "tunable", |s, f| write!(
    f,
    "{} {}",
    s.name, s.value
));
decl_display!(TypeAliasDecl, "typealias", |s, f| write!(
    f,
    "{} alias {}",
    s.ty, s.aliases
));
decl_display!(TypeAttributeDecl, "typeattribute", |s, f| write!(
    f,
    "{} {}",
    s.attribute, s.types
));
decl_display!(TypeBoundsDecl, "typebounds", |s, f| write!(
    f,
    "{} {}",
    s.ty, s.bounds
));
decl_display!(RoleAttributeDecl, "roleattribute", |s, f| write!(
    f,
    "{} {}",
    s.attribute, s.roles
));
decl_display!(RoleTypesDecl, "role", |s, f| write!(
    f,
    "{} types {}",
    s.role, s.types
));
decl_display!(DominanceDecl, "dominance", |s, f| fmt::Display::fmt(
    &s.sensitivities,
    f
));
impl fmt::Display for CommonDecl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "common {} {{ {} }}", self.common, self.permissions)?;
        if self.terminator.is_some() {
            f.write_str(";")?;
        }
        writeln!(f)
    }
}
decl_display!(DefaultUserDecl, "default_user", |s, f| write!(
    f,
    "{} {}",
    s.classes, s.target
));
decl_display!(DefaultRoleDecl, "default_role", |s, f| write!(
    f,
    "{} {}",
    s.classes, s.target
));
decl_display!(DefaultTypeDecl, "default_type", |s, f| write!(
    f,
    "{} {}",
    s.classes, s.target
));

impl fmt::Display for ExpandAttributeDecl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "expandattribute {} {};", self.attributes, self.expand)
    }
}

impl fmt::Display for TypeDecl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "type {}", self.ty)?;
        if let Some(aliases) = &self.aliases {
            write!(f, " alias {aliases}")?;
        }
        if let Some(attributes) = &self.attributes {
            write!(f, ", {attributes}")?;
        }
        writeln!(f, ";")
    }
}

impl fmt::Display for RoleDecl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "role {}", self.role)?;
        if let Some(attributes) = &self.attributes {
            write!(f, ", {attributes}")?;
        }
        writeln!(f, ";")
    }
}

impl fmt::Display for ClassPermissionsDecl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "class {}", self.class)?;
        if let Some(inherits) = &self.inherits {
            write!(f, " inherits {inherits}")?;
        }
        if let Some(permissions) = &self.permissions {
            write!(f, " {{ {permissions} }}")?;
        }
        if self.terminator.is_some() {
            f.write_str(";")?;
        }
        writeln!(f)
    }
}

impl fmt::Display for DefaultRangeDecl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "default_range {}", self.classes)?;
        match &self.target {
            DefaultRangeTarget::Glblub => write!(f, " glblub")?,
            DefaultRangeTarget::Sided { target, value } => write!(f, " {target} {value}")?,
        }
        writeln!(f, ";")
    }
}

impl fmt::Display for SensitivityDecl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sensitivity {}", self.sensitivity)?;
        if let Some(aliases) = &self.aliases {
            write!(f, " alias {aliases}")?;
        }
        writeln!(f, ";")
    }
}

impl fmt::Display for CategoryDecl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "category {}", self.category)?;
        if let Some(aliases) = &self.aliases {
            write!(f, " alias {aliases}")?;
        }
        writeln!(f, ";")
    }
}

impl fmt::Display for LevelDecl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "level {}", self.level)?;
        if let Some(categories) = &self.categories {
            write!(f, ":{categories}")?;
        }
        writeln!(f, ";")
    }
}

impl fmt::Display for UserDecl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "user {} roles {}", self.user, self.roles)?;
        if let Some(level) = &self.level {
            write!(f, " level {level}")?;
        }
        if let Some(range) = &self.range {
            write!(f, " range {range}")?;
        }
        writeln!(f, ";")
    }
}

impl fmt::Display for Declaration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Attribute(v) => fmt::Display::fmt(v, f),
            Self::ExpandAttribute(v) => fmt::Display::fmt(v, f),
            Self::Type(v) => fmt::Display::fmt(v, f),
            Self::TypeAlias(v) => fmt::Display::fmt(v, f),
            Self::TypeAttribute(v) => fmt::Display::fmt(v, f),
            Self::TypeBounds(v) => fmt::Display::fmt(v, f),
            Self::AttributeRole(v) => fmt::Display::fmt(v, f),
            Self::Role(v) => fmt::Display::fmt(v, f),
            Self::RoleAttribute(v) => fmt::Display::fmt(v, f),
            Self::RoleTypes(v) => fmt::Display::fmt(v, f),
            Self::Bool(v) => fmt::Display::fmt(v, f),
            Self::Tunable(v) => fmt::Display::fmt(v, f),
            Self::Permissive(v) => fmt::Display::fmt(v, f),
            Self::NeverAudit(v) => fmt::Display::fmt(v, f),
            Self::PolicyCap(v) => fmt::Display::fmt(v, f),
            Self::Class(v) => fmt::Display::fmt(v, f),
            Self::ClassPermissions(v) => fmt::Display::fmt(v, f),
            Self::Common(v) => fmt::Display::fmt(v, f),
            Self::InitialSid(v) => fmt::Display::fmt(v, f),
            Self::DefaultUser(v) => fmt::Display::fmt(v, f),
            Self::DefaultRole(v) => fmt::Display::fmt(v, f),
            Self::DefaultType(v) => fmt::Display::fmt(v, f),
            Self::DefaultRange(v) => fmt::Display::fmt(v, f),
            Self::Sensitivity(v) => fmt::Display::fmt(v, f),
            Self::Dominance(v) => fmt::Display::fmt(v, f),
            Self::Category(v) => fmt::Display::fmt(v, f),
            Self::Level(v) => fmt::Display::fmt(v, f),
            Self::User(v) => fmt::Display::fmt(v, f),
        }
    }
}

impl fmt::Display for RequireDecl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Class {
                class, permissions, ..
            } => match permissions {
                NameSet::Single(permission) => writeln!(f, "class {class} {permission};"),
                other => {
                    let inner = match other {
                        NameSet::Set(set) => set
                            .elements()
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(" "),
                        other => other.to_string(),
                    };
                    writeln!(f, "class {class} {{ {inner} }};")
                }
            },
            Self::Role(list, _) => writeln!(f, "role {list};"),
            Self::Type(list, _) => writeln!(f, "type {list};"),
            Self::Attribute(list, _) => writeln!(f, "attribute {list};"),
            Self::AttributeRole(list, _) => writeln!(f, "attribute_role {list};"),
            Self::User(list, _) => writeln!(f, "user {list};"),
            Self::Bool(list, _) => writeln!(f, "bool {list};"),
            Self::Tunable(list, _) => writeln!(f, "tunable {list};"),
            Self::Sensitivity(list, _) => writeln!(f, "sensitivity {list};"),
            Self::Category(list, _) => writeln!(f, "category {list};"),
        }
    }
}

impl fmt::Display for RequireBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "require {{")?;
        for declaration in &self.declarations {
            write!(f, "\t{declaration}")?;
        }
        writeln!(f, "}}")
    }
}

impl fmt::Display for GenRequireBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "gen_require(`")?;
        for declaration in &self.declarations {
            write!(f, "\t{declaration}")?;
        }
        writeln!(f, "')")
    }
}

impl fmt::Display for CondRuleList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for rule in &self.0 {
            write!(f, "\t{rule}")?;
        }
        Ok(())
    }
}

impl fmt::Display for CondRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transition(v) => fmt::Display::fmt(v, f),
            Self::AvTab(v) => fmt::Display::fmt(v, f),
            Self::XPerm(v) => fmt::Display::fmt(v, f),
            Self::Require(v) => fmt::Display::fmt(v, f),
            Self::Comment(v) => writeln!(f, "{v}"),
            Self::DocComment(v) => writeln!(f, "{v}"),
            Self::Macro(v) => fmt::Display::fmt(v, f),
        }
    }
}

impl fmt::Display for ConditionalBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "if {} {{", self.expression)?;
        for rule in self.then.rules() {
            write!(f, "\t{rule}")?;
        }
        if let Some(otherwise) = &self.otherwise {
            writeln!(f, "}} else {{")?;
            for rule in otherwise.rules() {
                write!(f, "\t{rule}")?;
            }
        }
        writeln!(f, "}}")
    }
}

impl fmt::Display for OptionalBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "optional {{")?;
        write!(f, "{}", indent(&self.body))?;
        if let Some(otherwise) = &self.otherwise {
            writeln!(f, "}} else {{")?;
            write!(f, "{}", indent(otherwise))?;
        }
        writeln!(f, "}}")
    }
}

fn indent(list: &StatementList) -> String {
    use std::fmt::Write as _;
    list.0.iter().fold(String::new(), |mut out, statement| {
        let _ = write!(out, "\t{statement}");
        out
    })
}

impl fmt::Display for MacroStatement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GenRequire(v) => fmt::Display::fmt(v, f),
            Self::OptionalPolicy(v) => fmt::Display::fmt(v, f),
            Self::TunablePolicy(v) => fmt::Display::fmt(v, f),
            Self::GenBool(v) => fmt::Display::fmt(v, f),
            Self::GenTunable(v) => fmt::Display::fmt(v, f),
            Self::Conditional(v) => {
                write!(f, "{}(`{}',`", v.kind, v.symbol)?;
                write!(f, "{}", indent(&v.then))?;
                if let Some(otherwise) = &v.otherwise {
                    write!(f, "',`{}", indent(otherwise))?;
                }
                writeln!(f, "')")
            }
            Self::IfElse(v) => fmt::Display::fmt(v, f),
            Self::Definition(v) => fmt::Display::fmt(v, f),
            Self::Module(v) => fmt::Display::fmt(v, f),
            Self::Dnl(v) => writeln!(f, "{v}"),
            Self::Invocation(v) => fmt::Display::fmt(v, f),
        }
    }
}

impl fmt::Display for ConstraintStatement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Constrain(v) => fmt::Display::fmt(v, f),
            Self::MlsConstrain(v) => {
                write!(f, "mls")?;
                fmt::Display::fmt(v, f)
            }
            Self::ValidateTrans(v) => fmt::Display::fmt(v, f),
            Self::MlsValidateTrans(v) => {
                write!(f, "mls")?;
                fmt::Display::fmt(v, f)
            }
        }
    }
}

impl fmt::Display for ConstrainDecl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "constrain {} {} ({});",
            self.classes, self.permissions, self.expression
        )
    }
}

impl fmt::Display for ValidateTransDecl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "validatetrans {} ({});", self.classes, self.expression)
    }
}

impl fmt::Display for ContextStatement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InitialSidContext(v) => {
                write!(f, "sid {} {}", v.sid, v.context)?;
                if v.terminator.is_some() {
                    f.write_str(";")?;
                }
                writeln!(f)
            }
            Self::FsUse(v) => writeln!(f, "{} {} {};", v.kind.as_str(), v.filesystem, v.context),
            Self::GenfsCon(v) => {
                write!(f, "genfscon {} {}", v.filesystem, v.path)?;
                match v.file_type {
                    Some(GenfsFileType::Any) => write!(f, " --")?,
                    Some(GenfsFileType::Kind(kind)) => write!(f, " -{kind}")?,
                    None => {}
                }
                write!(f, " {}", v.context)?;
                if v.terminator.is_some() {
                    f.write_str(";")?;
                }
                writeln!(f)
            }
            Self::PortCon(v) => write_context_line(
                f,
                &format!("portcon {} {}", v.protocol.as_str(), v.ports),
                &v.context,
                v.terminator.is_some(),
            ),
            Self::NetifCon(v) => {
                write!(
                    f,
                    "netifcon {} {} {}",
                    v.interface, v.interface_context, v.packet_context
                )?;
                if v.terminator.is_some() {
                    f.write_str(";")?;
                }
                writeln!(f)
            }
            Self::NodeCon(v) => {
                let address = match &v.address {
                    NodeAddress::V4Pair(a, m) => format!("{a} {m}"),
                    NodeAddress::V4Cidr(n) => n.to_string(),
                    NodeAddress::V6Pair(a, m) => format!("{a} {m}"),
                    NodeAddress::V6Cidr(n) => n.to_string(),
                };
                write_context_line(
                    f,
                    &format!("nodecon {address}"),
                    &v.context,
                    v.terminator.is_some(),
                )
            }
            Self::PirqCon(v) => write_context_line(
                f,
                &format!("pirqcon {}", v.irq),
                &v.context,
                v.terminator.is_some(),
            ),
            Self::IomemCon(v) => write_context_line(
                f,
                &format!("iomemcon {}", v.memory),
                &v.context,
                v.terminator.is_some(),
            ),
            Self::IoportCon(v) => write_context_line(
                f,
                &format!("ioportcon {}", v.ports),
                &v.context,
                v.terminator.is_some(),
            ),
            Self::PciDeviceCon(v) => write_context_line(
                f,
                &format!("pcidevicecon {}", v.device),
                &v.context,
                v.terminator.is_some(),
            ),
            Self::DeviceTreeCon(v) => write_context_line(
                f,
                &format!("devicetreecon {}", v.path),
                &v.context,
                v.terminator.is_some(),
            ),
            Self::IbPkeyCon(v) => {
                let pkeys = match &v.pkeys {
                    Some(range) => format!(" {range}"),
                    None => String::new(),
                };
                write_context_line(
                    f,
                    &format!("ibpkeycon {}{pkeys}", v.subnet),
                    &v.context,
                    v.terminator.is_some(),
                )
            }
            Self::IbEndPortCon(v) => write_context_line(
                f,
                &format!("ibendportcon {} {}", v.device, v.port),
                &v.context,
                v.terminator.is_some(),
            ),
        }
    }
}

impl fmt::Display for FsUseKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

fn write_context_line(
    f: &mut fmt::Formatter<'_>,
    prefix: &str,
    context: &ContextValue,
    terminated: bool,
) -> fmt::Result {
    write!(f, "{prefix} {context}")?;
    if terminated {
        f.write_str(";")?;
    }
    writeln!(f)
}

impl fmt::Display for RangeTransitionRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "range_transition {} {}", self.source, self.target)?;
        if let Some(classes) = &self.classes {
            write!(f, ":{classes}")?;
        }
        writeln!(f, " {};", self.range)
    }
}

impl fmt::Display for RoleTransitionRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "role_transition {} {}", self.source, self.target)?;
        if let Some(classes) = &self.classes {
            write!(f, ":{classes}")?;
        }
        writeln!(f, " {};", self.result)
    }
}

impl fmt::Display for ModuleDecl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "policy_module({}", self.name)?;
        if let Some(version) = &self.version {
            write!(f, ",{version}")?;
        }
        writeln!(f, ")")
    }
}

impl fmt::Display for OptionalPolicyBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "optional_policy(`")?;
        write!(f, "{}", indent(&self.body))?;
        writeln!(f, "')")
    }
}

impl fmt::Display for TunablePolicyBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "tunable_policy(`{}',`", self.condition)?;
        write!(f, "{}", indent(&self.body))?;
        if let Some(otherwise) = &self.otherwise {
            write!(f, "',`{}", indent(otherwise))?;
        }
        writeln!(f, "')")
    }
}

impl fmt::Display for GenBoolDecl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "gen_bool({}, {})", self.name, self.value)
    }
}

impl fmt::Display for GenTunableDecl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "gen_tunable({}, {})", self.name, self.value)
    }
}

impl fmt::Display for InitialSidContextDecl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sid {} {}", self.sid, self.context)?;
        if self.terminator.is_some() {
            f.write_str(";")?;
        }
        writeln!(f)
    }
}
