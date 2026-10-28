#!/usr/bin/env python3
"""Generate self-contained NixOS SELinux modules from the Reference Policy tree.

Every ``<module>.{if,te,fc}`` / ``<module>.{if,te}.in`` under
``policy/modules/<layer>/`` becomes a NixOS module at
``nixos/modules/base/<layer>/<module>.nix``:

* ``interface``       -- the ``.if`` file converted to the documentation and
  export schema,
* ``typeEnforcement`` -- the ``.te`` file converted to a string, wrapped in
  ``lib.mkBefore`` so a hand-written declaration of the same module wins,
* ``fileContext``     -- the ``.fc`` file converted to ``rules``.

All parsing and Nix rendering is delegated to the ``sepol2nix`` binary: this
script only walks the tree, assembles the module wrappers, and writes the
indexing modules. ``sepol2nix`` itself is built from the flake first.

``/usr`` file-context rules are emitted as commented references for every
module. Modules in `STRIP_USR` keep only those references (their store analogue
is hand-written); every other module is additionally rendered with
``--substitute-usr nix-store``.

The refpolicy source is resolved from ``nixos/refpolicy.nix`` by evaluating the
very same package the tests use:

    nix build .#checks.x86_64-linux.selinux-enforce.nodes.machine.security.selinux.refpolicy.src

Pass ``--src`` (or set ``REFPOLICY_SRC``) to point at an already-materialised
tree instead. Should the flake fail to evaluate because a generated file is
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
from pathlib import Path

# --------------------------------------------------------------------------
# Configuration -- everything a human is expected to touch lives here.
# --------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = REPO_ROOT / "nixos" / "modules" / "base"

TOOL_ATTR = ".#sepol2nix"

#: Flake attribute that resolves `config.security.selinux.refpolicy.src`.
REFPOLICY_SRC_ATTR = (
    ".#checks.x86_64-linux.selinux-enforce.nodes.machine.security.selinux.refpolicy.src"
)

#: Reference Policy layers we do not translate at all.
IGNORED_LAYERS = {}

#: Module name globs (``fnmatch``, not regex) that are skipped entirely.
IGNORED_MODULES = [
    # `corenetwork` compiles only after its `.te.m4` definitions are expanded
    # through the Reference Policy's `gennetfilter` Makefile rule; a plain `.te`
    # from the `.te.in` template would leave `network_*` macros to `checkpolicy`.
    # The refpolicy pipeline owns this module.
    "corenetwork",
]

#: Module name globs whose `/usr` rules are *not* rendered as live store rules.
#: Those modules' real file contexts are hand-written (the store analogue of
#: `/usr` differs per module), so they keep only the commented-out upstream
#: reference lines.
STRIP_USR = [
    "dbus",
    "docportal",
    "fail2ban",
    "init",
    "logging",
    "nscd",
    "pipewire",
    "selinuxutil",
    "systemd",
]

# --------------------------------------------------------------------------
# Tool and source resolution
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


def build_tool() -> Path:
    """Builds sepol2nix and returns its executable path."""
    cmd = ["nix", "build", TOOL_ATTR, "--no-link", "--print-out-paths"]
    print(f"$ {' '.join(cmd)}", file=sys.stderr)
    result = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
        raise SystemExit("failed to build sepol2nix")
    return Path(result.stdout.strip().splitlines()[-1]) / "bin" / "sepol2nix"


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


# --------------------------------------------------------------------------
# Conversion
# --------------------------------------------------------------------------


def convert(tool: Path, source: Path, extra_args: list[str] | None = None) -> str:
    """Runs sepol2nix over one source file and returns its Nix expression."""
    cmd = [str(tool), "nix", str(source), *(extra_args or [])]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
        raise SystemExit(f"failed to convert {source}")
    return result.stdout.rstrip("\n")


def embed(out: list[str], prefix: str, expression: str, indent: int) -> None:
    """Embeds an expression rendered at column zero below `prefix`.

    sepol2nix emits `nixfmt`-canonical expressions, so shifting every line by
    the binding indentation keeps nixfmt's relative layout intact.
    """
    pad = " " * indent
    lines = expression.split("\n")
    out.append(prefix + lines[0])
    for line in lines[1:]:
        out.append(pad + line if line else "")
    out[-1] += ";"


def render_module(
    module: str,
    layer: str,
    interface: str,
    type_enforcement: str,
    rules: str,
) -> str:
    out = [
        "# Generated by scripts/gen-base.py using sepol2nix, from the Reference Policy source.",
        "# Do not edit manually; re-run the generator instead.",
        "{ lib, ... }: {",
        f"  config.security.selinux.modules.{module} = {{",
        f'    layer = "{layer}";',
    ]
    embed(out, "    interface = ", interface, 4)
    embed(out, "    typeEnforcement = lib.mkBefore ", type_enforcement, 4)
    out.append("    fileContext = {")
    embed(out, "      rules = ", rules, 6)
    out.append("    };")
    out.append("  };")
    out.append("}")
    return "\n".join(out) + "\n"


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


def module_files(base: Path) -> tuple[Path, Path, Path]:
    """Resolves a module's `.if`, `.te` and `.fc` source, preferring `.in`."""
    interface = base.with_suffix(".if")
    if not interface.exists():
        interface = base.with_suffix(".if.in")
    te = base.with_suffix(".te")
    if not te.exists():
        te = base.with_suffix(".te.in")
    return interface, te, base.with_suffix(".fc")


def module_names(src: Path, layer: str) -> list[str]:
    """Module stems in `layer`, including those shipped as `.in` templates."""
    stems = set()
    for entry in (src / "policy" / "modules" / layer).iterdir():
        name = entry.name
        if name.endswith((".if.in", ".te.in", ".fc.in")):
            stems.add(name[: -len(".in")][: -len(".if")])
        elif entry.suffix in (".if", ".te", ".fc"):
            stems.add(entry.stem)
    return sorted(stems)


# --------------------------------------------------------------------------
# Driver
# --------------------------------------------------------------------------


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

    tool = build_tool()
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
            interface_path, te_path, fc_path = module_files(base)
            if not fc_path.exists():
                print(f"skip {layer}/{module}: no .fc", file=sys.stderr)
                continue
            strip_usr = any(fnmatch.fnmatch(module, pattern) for pattern in STRIP_USR)
            substitution = [] if strip_usr else ["--substitute-usr", "nix-store"]
            interface = convert(tool, interface_path)
            type_enforcement = convert(tool, te_path)
            rules = convert(tool, fc_path, substitution)

            target = out_root / layer / f"{module}.nix"
            generated.append(target)
            layer_imports.setdefault(layer, []).append(f"./{module}.nix")
            per_layer[layer] = per_layer.get(layer, 0) + 1
            if args.dry_run:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(
                render_module(module, layer, interface, type_enforcement, rules)
            )

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

    print(f"tool: {tool}")
    print(f"source: {src}")
    for layer, count in per_layer.items():
        print(f"  {layer}: {count} modules")
    print(
        f"total: {len(generated)} modules, {len(indexes)} index modules -> {out_root}"
    )
    if args.dry_run:
        print("dry run: nothing written")
    return 0


if __name__ == "__main__":
    sys.exit(main())
