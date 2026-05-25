import os
import fnmatch
from pathlib import Path
from typing import Set, Optional


def load_tree_rules() -> Set[str]:
    current_script_name = Path(__file__).name
    always_hide = {
        '.git', '__pycache__', current_script_name, '.pytest_cache',
        '.venv', 'venv', 'env', '.uv', '.vscode', '.idea', '.DS_Store',
        'build', 'dist', '*.egg-info'
    }
    return always_hide


def should_ignore(name: str, rules: Set[str]) -> bool:
    for rule in rules:
        if fnmatch.fnmatch(name, rule):
            return True
    return False


def get_ai_metadata(item: Path) -> str:
    name = item.name.lower()

    if item.is_dir():
        metadata_map = {
            'app': "[Core: Main Application Package]",
            'routers': "[FastAPI: Route Handlers]",
            'schemas': "[Pydantic: Data Models]",
            'db': "[Database: Connection & Session Logic]",
            'models': "[ORM: Database Tables]",
            'core': "[Configuration: Settings & Middleware]"
        }
        return metadata_map.get(name, "")

    metadata_map = {
        'main.py': "[FastAPI: Application Entry Point]",
        'requirements.txt': "[Dependencies: pip]",
        'pyproject.toml': "[Dependencies: Project Config]",
        '.env': "[SECRETS: Environment Variables]",
        '.env.example': "[TEMPLATE: Environment Variables]",
        'database.py': "[Database: Connection Settings]"
    }

    if name in metadata_map:
        return f" {metadata_map[name]}"

    if name.endswith('.db') or name.endswith('.sqlite3'):
        return " [Local Database File]"

    return ""


def clone_tree_for_ai(path: Path, indent_level: int = 0, ignore_rules: Optional[Set[str]] = None) -> None:
    if ignore_rules is None:
        ignore_rules = load_tree_rules()

    try:
        items = sorted(list(path.iterdir()), key=lambda x: (
            not x.is_dir(), x.name.lower()))
    except PermissionError:
        return

    filtered_items = [item for item in items if not should_ignore(
        item.name, ignore_rules)]

    for item in filtered_items:
        spacing = "  " * indent_level
        icon = "📁" if item.is_dir() else "📄"
        metadata = get_ai_metadata(item)

        print(f"{spacing}- {icon} {item.name}{metadata}")

        if item.is_dir():
            clone_tree_for_ai(item, indent_level + 1, ignore_rules)


if __name__ == '__main__':
    root_path = Path('.')
    project_name = root_path.resolve().name

    print(f"<fastapi_project_tree name=\"{project_name}\">")
    clone_tree_for_ai(root_path)
    print("</fastapi_project_tree>")
