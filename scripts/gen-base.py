#!/usr/bin/env python3
"""Generate self-contained NixOS SELinux modules from the Reference Policy tree.

For every module in the Reference Policy source tree (every combination of
``<module>.{if,te,fc}`` under ``policy/modules/<layer>/``) this writes a NixOS
module to ``nixos/modules/base/<layer>/<module>.nix`` carrying:

* ``interface``     -- the verbatim contents of the module's ``.if`` file,
* ``typeEnforcement``-- the verbatim contents of the module's ``.te`` file,
* ``fileContext.rules`` -- the module's ``.fc`` rules parsed into an attribute
  set of ``path = "rule"`` (a list when several rules share one path).

Every layer directory additionally gets an indexing ``default.nix`` that imports
all of its modules, and ``nixos/modules/base/default.nix`` imports every layer,
so the whole tree can be pulled in with a single ``imports = [ ./base ];``.

The ``.if``/``.te`` bodies are left as-is on purpose: they still require the
Reference Policy's ``m4`` pre-processing (``interface`` templates, ``gen_bool``
and friends are only expanded at build time).  Only the ``distro_*`` conditional
blocks are stripped, since they are dead code for our ``DISTRO=nixos`` build and
our rule syntax cannot represent them.  ``.fc`` files, whose rules *do* have to
lose their conditionals (the attribute set cannot express them), are instead
fully resolved against the `ACTIVE_DEFINES` of our build.  `/usr` is rewritten to
a `/nix/store/[^/]+` glob, except for the modules listed in `STRIP_USR`, whose
upstream `/usr` rules are emitted commented out as a reference for the
hand-written store rules.

The output is byte-for-byte what ``nixfmt`` 1.4.0 (the version pinned by the
repo's treefmt) produces, so the generated tree is always clean under
``nix checks.x86_64-linux.treefmt``.

The refpolicy source is resolved from ``nixos/refpolicy.nix`` by evaluating the
very same package the tests use:

    nix build .#checks.x86_64-linux.selinux-enforce.nodes.machine.security.selinux.refpolicy.src

Pass ``--src`` (or set ``REFPOLICY_SRC``) to point at an already-materialised
tree instead.  Should the flake fail to evaluate because a generated file is
untracked (``nixos/modules/default.nix`` imports the generated tree), the paths
Nix reports are registered with ``git add -N`` and the resolution is retried.
"""

from __future__ import annotations

import argparse
import fnmatch
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

# --------------------------------------------------------------------------
# Configuration -- everything a human is expected to touch lives here.
# --------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = REPO_ROOT / "nixos" / "modules" / "base"

#: Flake attribute that resolves `config.security.selinux.refpolicy.src`.
REFPOLICY_SRC_ATTR = (
    ".#checks.x86_64-linux.selinux-enforce.nodes.machine.security.selinux.refpolicy.src"
)

#: Reference Policy layers we do not translate at all.
IGNORED_LAYERS = {}

#: Module name globs (``fnmatch``, not regex) that are skipped entirely.
IGNORED_MODULES = [
    # `corenetwork` has no plain `.if`/`.te`: the Reference Policy Makefile
    # generates them from `.if.in`/`.te.in` through `gennetfilter` (network port
    # macros), so there is no verbatim source to embed here.
    "corenetwork",
]

#: Module name globs (``fnmatch``, not regex) whose `/usr` rules are *not*
#: rewritten to the Nix store.  Those modules' real file contexts are
#: hand-written (the store analogue of `/usr` differs per module), so their
#: upstream `/usr` rules are kept in the generated file as commented-out
#: reference lines instead of being substituted or dropped.
STRIP_USR = [
    "dbus",
    "fail2ban",
    "init",
    "logging",
    "nscd",
    "pipewire",
    "selinuxutil",
    "systemd",
]

#: Top-level directories that exist on a NixOS system.  A `.fc` rule whose first
#: path component is not listed here (`/opt`, `/srv`, `/mnt`, `/media`, ...) is
#: dropped, together with any comment section that only covered it.  Rules that
#: live directly at the root (`/.*`, `/vmlinuz.*`, ...) have no component and are
#: always kept.
KEEP_TOPLEVEL = {
    "boot",
    "dev",
    "etc",
    "home",
    "nix",
    "proc",
    "root",
    "run",
    "sys",
    "tmp",
    "var",
}

#: `/usr` is the FHS analogue of the Nix store; rewrite it to a store glob.  The
#: store hash varies per path, hence the `[^/]+` component.
USR_SUBST = ("/usr", "/nix/store/[^/]+")

#: m4 symbols that are defined for our build (`DISTRO=nixos SYSTEMD=y UBAC=y
#: TYPE=mcs`).  Only used when resolving every conditional, i.e. for `.fc`
#: files, which have no `m4` stage in front of them once embedded in Nix.
ACTIVE_DEFINES = {
    "distro_nixos",
    "init_systemd",
    "enable_mcs",
    "enable_ubac",
}

#: Non-absolute refpolicy macros that stand for user home directories.  They are
#: resolved by `genhomedircon` at runtime, so they are carried over verbatim.
HOME_MACROS = ("HOME_DIR", "HOME_ROOT")

#: File-type flag token that may precede the context in a `.fc` rule.
FLAGS_RE = re.compile(r"^-+[a-zA-Z]*$")


# --------------------------------------------------------------------------
# m4 conditional handling
# --------------------------------------------------------------------------


def parse_call(text: str, start: int):
    """Parse the m4 macro call beginning at ``start``.

    Returns ``(name, args, end)`` where ``args`` are the raw (still quoted)
    argument texts and ``end`` is the index just past the closing parenthesis,
    or ``None`` when ``start`` does not begin a parenthesised macro call.
    """
    i = start
    while i < len(text) and (text[i].isalnum() or text[i] == "_"):
        i += 1
    name = text[start:i]
    if not name or i >= len(text) or text[i] != "(":
        return None

    i += 1
    args: list[str] = []
    buf: list[str] = []
    quote_depth = 0
    paren_depth = 0
    while i < len(text):
        c = text[i]
        if c == "`":
            quote_depth += 1
        elif c == "'" and quote_depth > 0:
            quote_depth -= 1
        elif quote_depth == 0:
            if c == "(":
                paren_depth += 1
            elif c == ")":
                if paren_depth == 0:
                    args.append("".join(buf))
                    return name, args, i + 1
                paren_depth -= 1
            elif c == "," and paren_depth == 0:
                args.append("".join(buf))
                buf = []
                i += 1
                continue
        buf.append(c)
        i += 1
    return None


def unquote(arg: str) -> str:
    """Strip one level of m4 quoting (``\\`...'``) from an argument."""
    arg = arg.strip()
    if len(arg) >= 2 and arg[0] == "`" and arg[-1] == "'":
        return arg[1:-1]
    return arg


CONDITIONALS = ("ifdef", "ifndef")


def expand_conditionals(text: str, resolve_all: bool) -> str:
    """Process ``ifdef``/``ifndef`` blocks in ``text``.

    With ``resolve_all`` set (used for ``.fc``), every conditional is evaluated
    against :data:`ACTIVE_DEFINES` and replaced by the branch that survives.
    Otherwise, only blocks conditioned on a ``distro_*`` symbol are resolved;
    all other conditionals are kept verbatim so the Reference Policy's own m4
    stage (which we still rely on for ``.if``/``.te``) sees them unchanged.
    """
    out: list[str] = []
    i = 0
    while i < len(text):
        c = text[i]
        if c.isalpha() or c == "_":
            call = parse_call(text, i)
            if call is not None:
                name, args, end = call
                if name in CONDITIONALS and len(args) >= 2:
                    cond = unquote(args[0]).strip()
                    then_body = unquote(args[1])
                    else_body = unquote(args[2]) if len(args) >= 3 else ""
                    is_distro = cond.startswith("distro_")
                    if resolve_all:
                        truth = cond in ACTIVE_DEFINES
                        if name == "ifndef":
                            truth = not truth
                        out.append(
                            expand_conditionals(
                                then_body if truth else else_body, resolve_all
                            )
                        )
                    elif is_distro:
                        # `ifdef(distro_x)` is false and `ifndef(distro_x)` is
                        # true for DISTRO=nixos, so keep the corresponding body.
                        keep_then = name == "ifndef"
                        out.append(
                            expand_conditionals(
                                then_body if keep_then else else_body, resolve_all
                            )
                        )
                    else:
                        # Not ours: keep it verbatim, but still recurse into the
                        # arguments so nested distro blocks are handled.
                        kept = ",".join(
                            expand_conditionals(a, resolve_all) for a in args
                        )
                        out.append(f"{name}({kept})")
                    i = end
                    continue
        out.append(c)
        i += 1
    return "".join(out)


# --------------------------------------------------------------------------
# `.fc` parsing
# --------------------------------------------------------------------------


@dataclass
class Rule:
    path: str
    value: str
    text: str  # key rendered into Nix (`/usr` substituted unless commented out)
    commented: bool = False


@dataclass
class Section:
    comments: list[str] = field(default_factory=list)
    body: list[object] = field(default_factory=list)  # Rule or None (blank line)


#: Top-level components that were seen but dropped, for reporting.
dropped_components: dict[str, int] = {}


def first_component(path: str) -> str:
    """Return the literal first path component of an absolute `.fc` path."""
    rest = path[1:]
    for idx, ch in enumerate(rest):
        if ch == "/" or ch in "()[]{}|\\^$*+?":
            return rest[:idx]
    return rest


def substitute_usr(path: str) -> str:
    src, dst = USR_SUBST
    if path == src:
        return dst
    if path.startswith(src + "/"):
        return dst + path[len(src) :]
    return path


def keep_path(path: str) -> bool:
    """Decide whether a `.fc` path is meaningful on NixOS."""
    if not path.startswith("/"):
        return path.startswith(HOME_MACROS)
    new = substitute_usr(path)
    if "/" not in new[1:]:
        # A root-level entry such as `/.*` or `/vmlinuz.*`.
        return True
    component = first_component(new)
    if component in KEEP_TOPLEVEL:
        return True
    dropped_components[component] = dropped_components.get(component, 0) + 1
    return False


def parse_fc(text: str, module: str, strip_usr: bool = False) -> list[Section]:
    text = expand_conditionals(text, resolve_all=True)
    # `dnl` is an m4 "delete to end of line" comment.  Once the conditionals are
    # resolved it only survives as noise (e.g. `')dnl end distro_redhat`), so
    # drop it instead of feeding it to the policy compiler.
    text = "\n".join(re.sub(r"\bdnl\b.*", "", line) for line in text.split("\n"))
    for keyword in ("ifdef(", "ifndef(", "ifelse("):
        if keyword in text:
            raise ValueError(f"{module}.fc: unresolved m4 construct {keyword!r}")

    sections: list[Section] = []
    current = Section()
    last_was_comment = False

    for raw in text.split("\n"):
        line = raw.strip()
        if not line:
            last_was_comment = False
            if current.body:
                current.body.append(None)
            continue
        if line.startswith("#"):
            # A comment block only continues the current section when it directly
            # follows the previous comment line; otherwise it heads a new one.
            if current.comments and (current.body or not last_was_comment):
                sections.append(current)
                current = Section()
            current.comments.append(raw.rstrip())
            last_was_comment = True
            continue
        last_was_comment = False

        tokens = line.split()
        path, rest = tokens[0], tokens[1:]
        if not path.startswith("/") and not path.startswith(HOME_MACROS):
            raise ValueError(f"{module}.fc: cannot parse rule {raw!r}")
        flag = ""
        if rest and FLAGS_RE.match(rest[0]):
            flag, rest = rest[0], rest[1:]
        context = " ".join(rest)
        if not context:
            raise ValueError(f"{module}.fc: rule without a context {raw!r}")
        if not (context.startswith("gen_context(") or context.startswith("<<none>>")):
            raise ValueError(f"{module}.fc: unexpected context {raw!r}")
        value = f"{flag} {context}" if flag else context

        if strip_usr and (path == USR_SUBST[0] or path.startswith(USR_SUBST[0] + "/")):
            # Keep the upstream `/usr` rule as a commented-out reference: the
            # store rules for these modules are hand-written.
            current.body.append(Rule(path=path, value=value, text=path, commented=True))
        elif keep_path(path):
            current.body.append(Rule(path=path, value=value, text=substitute_usr(path)))
        else:
            current.body.append(None)

    if current.comments or current.body:
        sections.append(current)
    return sections


def render_rules(sections: list[Section], module: str) -> str:
    """Render parsed sections as the body of a Nix attribute set."""
    values: dict[tuple[bool, str], list[str]] = {}
    for section in sections:
        for item in section.body:
            if isinstance(item, Rule):
                bucket = values.setdefault((item.commented, item.text), [])
                if item.value not in bucket:
                    bucket.append(item.value)

    emitted: set[tuple[bool, str]] = set()
    lines: list[str] = []
    for section in sections:
        kept = [i for i in section.body if isinstance(i, Rule)]
        if not kept:
            continue
        if lines:
            lines.append("")
        for comment in section.comments:
            lines.append(" " * 8 + comment)

        body: list[str] = []
        for item in section.body:
            if item is None:
                body.append("")
                continue
            identity = (item.commented, item.text)
            if identity in emitted:
                continue
            emitted.add(identity)
            body.append(
                render_assignment(item, values[identity], commented=item.commented)
            )
        while body and not body[0]:
            body.pop(0)
        while body and not body[-1]:
            body.pop()
        lines.extend(body)

    missing = set(values) - emitted
    if missing:
        raise AssertionError(f"{module}.fc: unreachable rules {sorted(missing)}")
    # nixfmt collapses runs of blank lines; keep the output canonical.
    collapsed: list[str] = []
    for line in lines:
        if not line and (not collapsed or not collapsed[-1]):
            continue
        collapsed.append(line)
    while collapsed and not collapsed[-1]:
        collapsed.pop()
    return "\n".join(collapsed)


def render_assignment(
    rule: Rule, rules: list[str], indent: int = 8, commented: bool = False
) -> str:
    """Render one `path = ...;` binding, wrapped exactly like nixfmt 1.4.0.

    nixfmt keeps a binding on a single line while its *content* (key, ` = `,
    value and `;`, but not the line's indentation) fits in 100 columns; beyond
    that it moves the value onto its own line and indents it by two.  Lists with
    more than one element always go on separate lines.

    With ``commented`` set, every line is preceded by the indentation and a
    `# ` marker (nixfmt leaves such lines alone), turning the binding into a
    reference comment.
    """
    pad = " " * indent
    marker = "# " if commented else ""

    def line(extra: int, text: str) -> str:
        return f"{pad}{marker}{' ' * extra}{text}"

    key = nix_dq(rule.text)
    if len(rules) == 1:
        value = nix_dq(rules[0])
        if len(key) + 3 + len(value) + 1 <= 100:
            return line(0, f"{key} = {value};")
        return "\n".join([line(0, f"{key} ="), line(2, f"{value};")])
    if len(key) + 3 + 1 <= 100:
        body = [line(2, nix_dq(value)) for value in rules]
        return "\n".join([line(0, f"{key} = ["), *body, line(0, "];")])
    body = [line(4, nix_dq(value)) for value in rules]
    return "\n".join([line(0, f"{key} ="), line(2, "["), *body, line(2, "];")])


# --------------------------------------------------------------------------
# Nix rendering
# --------------------------------------------------------------------------


def nix_dq(value: str) -> str:
    """Escape ``value`` for use inside a Nix double-quoted string.

    Nix silently drops the backslash of an unknown escape sequence, so the
    backslashes of the `.fc` regexes must be doubled to survive.
    """
    return (
        '"'
        + value.replace("\\", "\\\\").replace('"', '\\"').replace("${", "\\${")
        + '"'
    )


def nix_indented(value: str, indent: int = 6) -> str:
    """Escape and indent ``value`` for a Nix ``''`` string.

    Empty lines are emitted bare (no indentation): nixfmt writes them that way,
    and Nix evaluates an indentation-only line to the empty line anyway.
    """
    value = value.replace("''", "'''").replace("${", "''${")
    value = value.rstrip("\n")
    if not value:
        return ""
    prefix = " " * indent
    return "\n".join(prefix + line if line else "" for line in value.split("\n"))


def render_index(paths: list[str]) -> str:
    """Render an `imports`-only NixOS module listing ``paths``."""
    out = [
        "# Generated by scripts/gen-base.py from the Reference Policy source.",
        "# Do not edit manually; re-run the generator instead.",
        "{ ... }: {",
        "  imports = [",
    ]
    out.extend(f"    {path}" for path in paths)
    out.extend(["  ];", "}"])
    return "\n".join(out) + "\n"


def render_module(module: str, layer: str, interface: str, te: str, rules: str) -> str:
    out = [
        "# Generated by scripts/gen-base.py from the Reference Policy source.",
        "# Do not edit manually; re-run the generator instead.",
        "{ lib, ... }: {",
        f"  config.security.selinux.modules.{module} = {{",
        f'    layer = "{layer}";',
        "    interface = lib.mkBefore ''",
    ]
    if interface:
        out.append(nix_indented(interface))
    out.append("    '';")
    out.append("    typeEnforcement = lib.mkBefore ''")
    if te:
        out.append(nix_indented(te))
    out.append("    '';")
    out.append("    fileContext = {")
    out.append("      rules = {")
    if rules:
        out.append(rules)
    out.append("      };")
    out.append("    };")
    out.append("  };")
    out.append("}")
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------
# Driver
# --------------------------------------------------------------------------


#: Nix's hint for a path that a tracked flake file references but that the dirty
#: tree does not expose (untracked or intent-to-add).
GIT_ADD_HINT_RE = re.compile(r'git -C "[^"]*" add -N "([^"]+)"')

#: How many untracked paths we are willing to register before giving up.
GIT_ADD_ATTEMPTS = 16


def register_untracked(stderr: str) -> list[str]:
    """Stage (intent-to-add) the paths Nix reported as invisible, if any."""
    paths = GIT_ADD_HINT_RE.findall(stderr)
    for path in paths:
        subprocess.run(["git", "add", "-N", "--", path], cwd=REPO_ROOT, check=True)
    return paths


def resolve_source(src_arg: str | None) -> Path:
    if src_arg:
        return Path(src_arg)
    env = os.environ.get("REFPOLICY_SRC")
    if env:
        return Path(env)
    cmd = ["nix", "build", REFPOLICY_SRC_ATTR, "--no-link", "--print-out-paths"]
    print(f"$ {' '.join(cmd)}", file=sys.stderr)
    for _ in range(GIT_ADD_ATTEMPTS):
        result = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)
        if result.returncode == 0:
            return Path(result.stdout.strip().splitlines()[-1])
        # `nixos/modules/default.nix` imports the generated tree, so a fresh
        # (untracked) generated file makes the flake un-evaluable until it is
        # registered with git.  Nix names the offending path; do as it says.
        if not register_untracked(result.stderr):
            break
    sys.stderr.write(result.stderr)
    raise SystemExit("failed to resolve the refpolicy source")


def module_names(src: Path, layer: str) -> list[str]:
    stems = set()
    for entry in (src / "policy" / "modules" / layer).iterdir():
        if entry.suffix in (".if", ".te", ".fc"):
            stems.add(entry.stem)
    return sorted(stems)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--src", help="pre-materialised refpolicy source tree")
    parser.add_argument("--out", default=str(OUT_DIR), help="output directory")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="report what would be written, write nothing",
    )
    args = parser.parse_args()

    src = resolve_source(args.src)
    modules_root = src / "policy" / "modules"
    out_root = Path(args.out)

    layers = sorted(p.name for p in modules_root.iterdir() if p.is_dir())
    generated: list[Path] = []
    per_layer: dict[str, int] = {}
    layer_imports: dict[str, list[str]] = {}

    for layer in layers:
        if layer in IGNORED_LAYERS:
            continue
        for module in module_names(src, layer):
            if any(fnmatch.fnmatch(module, pattern) for pattern in IGNORED_MODULES):
                continue
            base = modules_root / layer / module
            fc_path = base.with_suffix(".fc")
            if not fc_path.exists():
                print(f"skip {layer}/{module}: no .fc", file=sys.stderr)
                continue
            interface = base.with_suffix(".if").read_text()
            te = base.with_suffix(".te").read_text()
            strip_usr = any(fnmatch.fnmatch(module, pattern) for pattern in STRIP_USR)
            rules = render_rules(
                parse_fc(fc_path.read_text(), module, strip_usr), module
            )
            content = render_module(
                module,
                layer,
                expand_conditionals(interface, resolve_all=False),
                expand_conditionals(te, resolve_all=False),
                rules,
            )
            target = out_root / layer / f"{module}.nix"
            generated.append(target)
            layer_imports.setdefault(layer, []).append(f"./{module}.nix")
            per_layer[layer] = per_layer.get(layer, 0) + 1
            if args.dry_run:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)

    # One indexing module per layer, plus one for the whole tree.
    indexes: dict[Path, str] = {
        out_root / layer / "default.nix": render_index(layer_imports[layer])
        for layer in sorted(layer_imports)
    }
    indexes[out_root / "default.nix"] = render_index(
        [f"./{layer}" for layer in sorted(layer_imports)]
    )

    if not args.dry_run:
        for path, content in indexes.items():
            path.write_text(content)
        # Remove stale generated files (e.g. after a module is dropped).
        keep = {p.resolve() for p in (*generated, *indexes)}
        for path in out_root.rglob("*.nix"):
            if path.resolve() not in keep:
                path.unlink()

    print(f"source: {src}")
    for layer, count in per_layer.items():
        print(f"  {layer}: {count} modules")
    print(
        f"total: {len(generated)} modules, {len(indexes)} index modules -> {out_root}"
    )
    if dropped_components:
        summary = ", ".join(
            f"/{k or '<root>'} ({v})" for k, v in sorted(dropped_components.items())
        )
        print(f"dropped top-level paths: {summary}")
    if args.dry_run:
        print("dry run: nothing written")
    return 0


if __name__ == "__main__":
    sys.exit(main())
