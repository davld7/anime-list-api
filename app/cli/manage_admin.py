import argparse
import getpass
import logging
import sys
from typing import Callable

from app.core.security import get_password_hash
from app.db.database import init_database
from app.repositories.user_repository import (
    count_active_admins as _count_active_admins,
)
from app.repositories.user_repository import (
    count_users as _count_users,
)
from app.repositories.user_repository import (
    create_user as _create_user,
)
from app.repositories.user_repository import (
    get_user_by_username as _get_user_by_username,
)
from app.repositories.user_repository import (
    update_user_by_id_atomic as _update_user_by_id_atomic,
)

logger = logging.getLogger("anime-api.cli")

ADMIN_PERMISSIONS = ["read", "write", "admin"]


def _confirm(input_fn: Callable[[str], str], prompt: str) -> bool:
    answer = input_fn(f"{prompt} [y/N]: ").strip().lower()
    return answer == "y"


def run_status(
    count_users_fn: Callable = _count_users,
    count_active_admins_fn: Callable = _count_active_admins,
    init_database_fn: Callable = init_database,
) -> int:
    init_database_fn()
    total_users = count_users_fn()
    active_admins = count_active_admins_fn()

    print(f"Total users: {total_users}")
    print(f"Active administrators: {active_admins}")

    if active_admins == 0:
        print("No active administrators. Administrative recovery is required.")

    return 0


def run_create(
    input_fn: Callable[[str], str] = input,
    getpass_fn: Callable[[str], str] = getpass.getpass,
    count_active_admins_fn: Callable = _count_active_admins,
    get_user_by_username_fn: Callable = _get_user_by_username,
    create_user_fn: Callable = _create_user,
    get_password_hash_fn: Callable = get_password_hash,
    init_database_fn: Callable = init_database,
) -> int:
    init_database_fn()

    if count_active_admins_fn() != 0:
        print("An active administrator already exists. Aborting.")
        return 1

    username = input_fn("Username: ").strip()
    if not username:
        print("Username cannot be empty. Aborting.")
        return 1

    if get_user_by_username_fn(username) is not None:
        print(f"Username '{username}' already exists. Aborting.")
        return 1

    password = getpass_fn("Password: ")
    confirmation = getpass_fn("Confirm password: ")
    if password != confirmation:
        print("Passwords do not match. Aborting.")
        return 1

    prompt = (
        f'About to create active administrator "{username}".\n'
        "Continue?"
    )
    if not _confirm(input_fn, prompt):
        print("Abort.")
        return 1

    user_data = {
        "username": username,
        "password_hash": get_password_hash_fn(password),
        "permissions": ADMIN_PERMISSIONS,
        "active": True,
        "auth_version": 1,
    }

    create_user_fn(user_data)

    print(f"Administrator '{username}' created successfully.")
    return 0


def run_reset_password(
    input_fn: Callable[[str], str] = input,
    getpass_fn: Callable[[str], str] = getpass.getpass,
    get_user_by_username_fn: Callable = _get_user_by_username,
    update_user_by_id_atomic_fn: Callable = _update_user_by_id_atomic,
    get_password_hash_fn: Callable = get_password_hash,
    init_database_fn: Callable = init_database,
) -> int:
    init_database_fn()

    username = input_fn("Username: ").strip()
    user = get_user_by_username_fn(username)
    if user is None:
        print(f"User '{username}' does not exist. Aborting.")
        return 1

    if "admin" not in user.get("permissions", []):
        print(f"User '{username}' is not an administrator. Aborting.")
        return 1

    if not user.get("active", True):
        print(f"Administrator '{username}' is inactive. Aborting.")
        return 1

    new_password = getpass_fn("New password: ")
    confirmation = getpass_fn("Confirm new password: ")
    if new_password != confirmation:
        print("Passwords do not match. Aborting.")
        return 1

    prompt = (
        f'About to reset the password for administrator "{username}".\n'
        "Existing sessions will be invalidated.\n"
        "Continue?"
    )
    if not _confirm(input_fn, prompt):
        print("Abort.")
        return 1

    password_hash = get_password_hash_fn(new_password)
    update_user_by_id_atomic_fn(
        user["_id"],
        {"password_hash": password_hash},
        {"auth_version": 1},
    )

    print(
        f"Password reset for administrator '{username}'. Existing sessions were invalidated."
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="manage_admin",
        description="On-demand administrative recovery CLI.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("status", help="Show administrative status.")
    subparsers.add_parser("create", help="Create a recovery administrator.")
    subparsers.add_parser("reset-password", help="Reset an active administrator password.")

    args = parser.parse_args(argv)

    if args.command == "status":
        return run_status()
    if args.command == "create":
        return run_create()
    if args.command == "reset-password":
        return run_reset_password()

    return 1


if __name__ == "__main__":
    sys.exit(main())
