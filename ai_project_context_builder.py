import fnmatch
from pathlib import Path
from typing import Set, Optional, Dict


# =========================
# IGNORE RULES
# =========================
def load_tree_rules() -> Set[str]:
    current_script_name = Path(__file__).name

    return {
        '.git', '__pycache__', current_script_name,
        '.pytest_cache', '.venv', 'venv', 'env',
        '.uv', '.vscode', '.idea', '.DS_Store',
        'build', 'dist', '*.egg-info',
        'node_modules'
    }


def should_ignore(name: str, rules: Set[str]) -> bool:
    return any(fnmatch.fnmatch(name, rule) for rule in rules)


# =========================
# ARCHITECTURE INTELLIGENCE
# =========================
def detect_layer(path: Path) -> str:
    name = path.name.lower()

    layer_map = {
        "app": "CORE APPLICATION",
        "core": "CONFIGURATION LAYER",
        "db": "DATABASE LAYER",
        "routers": "API ROUTERS LAYER",
        "schemas": "DATA CONTRACTS (DTOs)",
        "repositories": "DATA ACCESS LAYER",
        "tests": "TESTING LAYER",
    }

    return layer_map.get(name, "MODULE")


def get_file_role(file: Path) -> str:
    name = file.name.lower()

    roles = {
        "main.py": "FASTAPI ENTRY POINT",
        "database.py": "MONGODB CONNECTION + INFRASTRUCTURE",
        "config.py": "APPLICATION SETTINGS",
        "pyproject.toml": "PROJECT CONFIGURATION",
        "README.md": "DOCUMENTATION",
        ".env": "ENVIRONMENT SECRETS",
        "__init__.py": "PYTHON PACKAGE INIT",
    }

    if name in roles:
        return roles[name]

    if name.endswith(".py"):
        return "PYTHON MODULE"

    return "FILE"


# =========================
# TREE BUILDER
# =========================
def clone_tree_for_ai(
    path: Path,
    indent_level: int = 0,
    ignore_rules: Optional[Set[str]] = None,
    stats: Optional[Dict[str, int]] = None
) -> Dict[str, int]:

    if ignore_rules is None:
        ignore_rules = load_tree_rules()

    if stats is None:
        stats = {}

    try:
        items = sorted(
            list(path.iterdir()),
            key=lambda x: (not x.is_dir(), x.name.lower())
        )
    except PermissionError:
        return stats

    filtered_items = [
        item for item in items
        if not should_ignore(item.name, ignore_rules)
    ]

    for item in filtered_items:
        spacing = "  " * indent_level
        icon = "📁" if item.is_dir() else "📄"

        if item.is_dir():
            layer = detect_layer(item)
            stats[layer] = stats.get(layer, 0) + 1
            print(f"{spacing}- {icon} {item.name} [{layer}]")
            clone_tree_for_ai(item, indent_level + 1, ignore_rules, stats)
        else:
            role = get_file_role(item)
            stats[role] = stats.get(role, 0) + 1
            print(f"{spacing}- {icon} {item.name} [{role}]")

    return stats


# =========================
# SUMMARY REPORT
# =========================
def print_summary(stats: Dict[str, int]) -> None:
    print("\n")
    print("📊 PROJECT ARCHITECTURE SUMMARY")
    print("=" * 40)

    for key, value in sorted(stats.items(), key=lambda x: -x[1]):
        print(f"{key}: {value}")

    print("=" * 40)


# =========================
# MAIN
# =========================
if __name__ == '__main__':
    root_path = Path('.')
    project_name = root_path.resolve().name

    print(f"<ai_project_context_builder name=\"{project_name}\">")

    stats = clone_tree_for_ai(root_path)
    print_summary(stats)

    print("</ai_project_context_builder>")