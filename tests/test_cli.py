import os
from unittest.mock import Mock

import pytest

os.environ["MONGO_URI"] = "mongodb://localhost:27017"
os.environ["JWT_SECRET_KEY"] = "test-cli-secret-key-for-unit-tests"

from app.cli import manage_admin

NO_CONNECT = Mock(return_value=None)


def _username_then_confirm(username: str, confirm: str = "y"):
    def _input(prompt: str) -> str:
        if "Username" in prompt:
            return username
        return confirm

    return _input


class TestStatus:
    def test_status_shows_totals_with_an_active_admin(self, capsys):
        result = manage_admin.run_status(
            count_users_fn=Mock(return_value=3),
            count_active_admins_fn=Mock(return_value=1),
            init_database_fn=NO_CONNECT,
        )

        assert result == 0
        output = capsys.readouterr().out
        assert "Total users: 3" in output
        assert "Active administrators: 1" in output
        assert "recovery" not in output.lower()

    def test_status_warns_when_no_active_admins(self, capsys):
        result = manage_admin.run_status(
            count_users_fn=Mock(return_value=2),
            count_active_admins_fn=Mock(return_value=0),
            init_database_fn=NO_CONNECT,
        )

        assert result == 0
        output = capsys.readouterr().out
        assert "Total users: 2" in output
        assert "Active administrators: 0" in output
        assert "recovery is required" in output

    def test_status_never_exposes_sensitive_data(self, capsys):
        manage_admin.run_status(
            count_users_fn=Mock(return_value=1),
            count_active_admins_fn=Mock(return_value=1),
            init_database_fn=NO_CONNECT,
        )

        output = capsys.readouterr().out
        assert "password" not in output.lower()
        assert "MONGO" not in output
        assert "auth_version" not in output


class TestCreate:
    def test_create_creates_admin_when_no_active_admins(self):
        create_mock = Mock()
        result = manage_admin.run_create(
            input_fn=_username_then_confirm("operator"),
            getpass_fn=lambda _: "secret123",
            count_active_admins_fn=Mock(return_value=0),
            get_user_by_username_fn=Mock(return_value=None),
            create_user_fn=create_mock,
            get_password_hash_fn=Mock(return_value="hashed"),
            init_database_fn=NO_CONNECT,
        )
        create_mock.assert_called_once()
        created = create_mock.call_args.args[0]

        assert result == 0
        assert created["username"] == "operator"
        assert created["permissions"] == ["read", "write", "admin"]
        assert created["active"] is True
        assert created["auth_version"] == 1
        assert created["password_hash"] == "hashed"
        assert "password" not in created

    def test_create_aborts_when_active_admin_exists(self, capsys):
        create_mock = Mock()
        result = manage_admin.run_create(
            input_fn=_username_then_confirm("operator"),
            getpass_fn=lambda _: "secret123",
            count_active_admins_fn=Mock(return_value=1),
            get_user_by_username_fn=Mock(return_value=None),
            create_user_fn=create_mock,
            get_password_hash_fn=Mock(return_value="hashed"),
            init_database_fn=NO_CONNECT,
        )

        assert result == 1
        create_mock.assert_not_called()
        assert "already exists" in capsys.readouterr().out

    def test_create_aborts_when_username_already_exists(self, capsys):
        create_mock = Mock()
        result = manage_admin.run_create(
            input_fn=_username_then_confirm("operator"),
            getpass_fn=lambda _: "secret123",
            count_active_admins_fn=Mock(return_value=0),
            get_user_by_username_fn=Mock(return_value={"_id": "someid", "username": "operator"}),
            create_user_fn=create_mock,
            get_password_hash_fn=Mock(return_value="hashed"),
            init_database_fn=NO_CONNECT,
        )

        assert result == 1
        create_mock.assert_not_called()
        assert "already exists" in capsys.readouterr().out

    def test_create_aborts_when_passwords_do_not_match(self, capsys):
        create_mock = Mock()
        password_calls = iter(["secret123", "different"])
        result = manage_admin.run_create(
            input_fn=_username_then_confirm("operator"),
            getpass_fn=lambda _: next(password_calls),
            count_active_admins_fn=Mock(return_value=0),
            get_user_by_username_fn=Mock(return_value=None),
            create_user_fn=create_mock,
            get_password_hash_fn=Mock(return_value="hashed"),
            init_database_fn=NO_CONNECT,
        )

        assert result == 1
        create_mock.assert_not_called()
        assert "do not match" in capsys.readouterr().out

    def test_create_aborts_when_confirmation_rejected(self, capsys):
        create_mock = Mock()
        result = manage_admin.run_create(
            input_fn=_username_then_confirm("operator", confirm="n"),
            getpass_fn=lambda _: "secret123",
            count_active_admins_fn=Mock(return_value=0),
            get_user_by_username_fn=Mock(return_value=None),
            create_user_fn=create_mock,
            get_password_hash_fn=Mock(return_value="hashed"),
            init_database_fn=NO_CONNECT,
        )

        assert result == 1
        create_mock.assert_not_called()
        assert "Abort." in capsys.readouterr().out

    def test_create_never_modifies_existing_user(self):
        existing = {"_id": "someid", "username": "operator", "permissions": ["read"]}
        create_mock = Mock()
        manage_admin.run_create(
            input_fn=_username_then_confirm("operator"),
            getpass_fn=lambda _: "secret123",
            count_active_admins_fn=Mock(return_value=0),
            get_user_by_username_fn=Mock(return_value=existing),
            create_user_fn=create_mock,
            get_password_hash_fn=Mock(return_value="hashed"),
            init_database_fn=NO_CONNECT,
        )

        create_mock.assert_not_called()
        assert existing["permissions"] == ["read"]


class TestResetPassword:
    def _user(self, permissions=None, active=True):
        return {
            "_id": "a1b2c3",
            "username": "admin1",
            "password_hash": "old",
            "permissions": permissions or ["read", "write", "admin"],
            "active": active,
            "auth_version": 1,
        }

    def test_reset_aborts_when_user_not_found(self, capsys):
        update_mock = Mock()
        result = manage_admin.run_reset_password(
            input_fn=_username_then_confirm("admin1"),
            getpass_fn=lambda _: "newsecret",
            get_user_by_username_fn=Mock(return_value=None),
            update_user_by_id_atomic_fn=update_mock,
            get_password_hash_fn=Mock(return_value="hashed"),
            init_database_fn=NO_CONNECT,
        )

        assert result == 1
        update_mock.assert_not_called()
        assert "does not exist" in capsys.readouterr().out

    def test_reset_aborts_when_user_not_admin(self, capsys):
        update_mock = Mock()
        result = manage_admin.run_reset_password(
            input_fn=_username_then_confirm("admin1"),
            getpass_fn=lambda _: "newsecret",
            get_user_by_username_fn=Mock(return_value=self._user(permissions=["read"])),
            update_user_by_id_atomic_fn=update_mock,
            get_password_hash_fn=Mock(return_value="hashed"),
            init_database_fn=NO_CONNECT,
        )

        assert result == 1
        update_mock.assert_not_called()
        assert "not an administrator" in capsys.readouterr().out

    def test_reset_aborts_when_admin_inactive(self, capsys):
        update_mock = Mock()
        result = manage_admin.run_reset_password(
            input_fn=_username_then_confirm("admin1"),
            getpass_fn=lambda _: "newsecret",
            get_user_by_username_fn=Mock(return_value=self._user(active=False)),
            update_user_by_id_atomic_fn=update_mock,
            get_password_hash_fn=Mock(return_value="hashed"),
            init_database_fn=NO_CONNECT,
        )

        assert result == 1
        update_mock.assert_not_called()
        assert "inactive" in capsys.readouterr().out

    def test_reset_aborts_when_passwords_do_not_match(self, capsys):
        update_mock = Mock()
        password_calls = iter(["newsecret", "different"])
        result = manage_admin.run_reset_password(
            input_fn=_username_then_confirm("admin1"),
            getpass_fn=lambda _: next(password_calls),
            get_user_by_username_fn=Mock(return_value=self._user()),
            update_user_by_id_atomic_fn=update_mock,
            get_password_hash_fn=Mock(return_value="hashed"),
            init_database_fn=NO_CONNECT,
        )

        assert result == 1
        update_mock.assert_not_called()
        assert "do not match" in capsys.readouterr().out

    def test_reset_aborts_when_confirmation_rejected(self, capsys):
        update_mock = Mock()
        result = manage_admin.run_reset_password(
            input_fn=_username_then_confirm("admin1", confirm="n"),
            getpass_fn=lambda _: "newsecret",
            get_user_by_username_fn=Mock(return_value=self._user()),
            update_user_by_id_atomic_fn=update_mock,
            get_password_hash_fn=Mock(return_value="hashed"),
            init_database_fn=NO_CONNECT,
        )

        assert result == 1
        update_mock.assert_not_called()
        assert "Abort." in capsys.readouterr().out

    def test_reset_uses_hash_and_atomic_update_incrementing_auth_version(self):
        update_mock = Mock()
        hash_mock = Mock(return_value="newhashed")
        result = manage_admin.run_reset_password(
            input_fn=_username_then_confirm("admin1"),
            getpass_fn=lambda _: "newsecret",
            get_user_by_username_fn=Mock(return_value=self._user()),
            update_user_by_id_atomic_fn=update_mock,
            get_password_hash_fn=hash_mock,
            init_database_fn=NO_CONNECT,
        )

        assert result == 0
        hash_mock.assert_called_once_with("newsecret")
        update_mock.assert_called_once_with(
            "a1b2c3",
            {"password_hash": "newhashed"},
            {"auth_version": 1},
        )


class TestConfirm:
    def test_confirm_accepts_only_y(self):
        assert manage_admin._confirm(lambda _: "y", "Continue?") is True
        assert manage_admin._confirm(lambda _: "Y", "Continue?") is True

    @pytest.mark.parametrize("answer", ["n", "N", "", "yes", " "])
    def test_confirm_rejects_anything_else(self, answer):
        assert manage_admin._confirm(lambda _: answer, "Continue?") is False
