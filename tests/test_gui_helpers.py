from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import agileview_gui
from adapter import flatten_common_fields, sanitize_payload
from agileview_gui import (
    _ask_vault_path,
    _choose_vault_path,
    build_search_blob,
    combine_field_rows,
    flatten_for_table,
    get_show_secrets_enabled,
    pick_quick_fields,
    set_show_secrets_enabled,
    unlock_with_password_fallback,
)


class CopyFlowTests(unittest.TestCase):
    def test_hidden_mode_uses_masked_display_and_raw_copy(self) -> None:
        payload = {'fields': [{'designation': 'password', 'name': 'password', 'type': 'P', 'value': 'abc123'}]}
        compact = flatten_common_fields(payload)

        display_table_payload = {
            'title': 'Entry',
            'uuid': 'uuid-1',
            'category': 'Логины',
            'typeName': 'legacy.login',
            **sanitize_payload(compact),
            **sanitize_payload(payload),
        }
        copy_table_payload = {
            'title': 'Entry',
            'uuid': 'uuid-1',
            'category': 'Логины',
            'typeName': 'legacy.login',
            **compact,
            **payload,
        }

        display_rows = flatten_for_table(display_table_payload)
        copy_rows = flatten_for_table(copy_table_payload)
        combined = combine_field_rows(display_rows, copy_rows)

        password_row = next(row for row in combined if row.field == 'password')
        self.assertTrue(password_row.display_value.startswith('•'))
        self.assertEqual(password_row.copy_value, 'abc123')
        self.assertTrue(all('abc123' not in row.display_value for row in combined))

        quick_fields = pick_quick_fields(copy_rows)
        self.assertEqual(quick_fields.get('password'), 'abc123')

    def test_build_search_blob_includes_field_names_and_values(self) -> None:
        payload = {
            'title': 'My Entry',
            'fields': [{'name': 'username', 'value': 'alice@example.com'}],
            'sections': [{'title': 'SMTP'}],
        }
        blob = build_search_blob(payload)

        self.assertIn('fields', blob)
        self.assertIn('username', blob)
        self.assertIn('alice@example.com', blob)
        self.assertIn('smtp', blob)


class ReloadPolicyTests(unittest.TestCase):
    class FakeReader:
        def __init__(self, outcomes: list[Exception | None]):
            self._outcomes = list(outcomes)
            self.calls: list[str] = []

        def unlock(self, password: str) -> None:
            self.calls.append(password)
            outcome = self._outcomes.pop(0)
            if outcome is not None:
                raise outcome

    def test_success_with_cached_password(self) -> None:
        reader = self.FakeReader([None])

        result = unlock_with_password_fallback(reader, 'cached', lambda: 'unused')

        self.assertTrue(result.success)
        self.assertEqual(result.password, 'cached')
        self.assertEqual(reader.calls, ['cached'])
        self.assertFalse(result.prompted)

    def test_fallback_prompt_success(self) -> None:
        reader = self.FakeReader([ValueError('bad cached password'), None])

        result = unlock_with_password_fallback(reader, 'cached', lambda: 'new-password')

        self.assertTrue(result.success)
        self.assertEqual(result.password, 'new-password')
        self.assertEqual(reader.calls, ['cached', 'new-password'])
        self.assertTrue(result.prompted)
        self.assertIsNotNone(result.first_error)

    def test_prompt_cancel_keeps_current_session(self) -> None:
        reader = self.FakeReader([ValueError('bad cached password')])

        result = unlock_with_password_fallback(reader, 'cached', lambda: None)

        self.assertFalse(result.success)
        self.assertTrue(result.prompted)
        self.assertTrue(result.cancelled)
        self.assertEqual(result.password, 'cached')
        self.assertEqual(reader.calls, ['cached'])

    def test_prompt_retry_failure(self) -> None:
        reader = self.FakeReader([ValueError('bad cached password'), ValueError('bad new password')])

        result = unlock_with_password_fallback(reader, 'cached', lambda: 'wrong-new')

        self.assertFalse(result.success)
        self.assertTrue(result.prompted)
        self.assertFalse(result.cancelled)
        self.assertIsNotNone(result.first_error)
        self.assertIsNotNone(result.second_error)
        self.assertEqual(reader.calls, ['cached', 'wrong-new'])


class VaultPathSelectionTests(unittest.TestCase):
    def test_choose_vault_path_uses_existing_initial_path_without_dialog(self) -> None:
        with TemporaryDirectory() as temp_dir:
            vault_path = Path(temp_dir) / 'test.opvault'
            vault_path.mkdir()

            with patch('agileview_gui._make_hidden_root') as hidden_root_factory:
                chosen = _choose_vault_path(str(vault_path))

            self.assertEqual(chosen, vault_path.resolve())
            hidden_root_factory.assert_not_called()

    def test_ask_vault_path_returns_resolved_path(self) -> None:
        with TemporaryDirectory() as temp_dir:
            vault_path = Path(temp_dir) / 'vault.agilekeychain'
            vault_path.mkdir()

            with patch('agileview_gui.filedialog.askdirectory', return_value=str(vault_path)):
                chosen = _ask_vault_path(parent=None, initial_dir=None)

            self.assertEqual(chosen, vault_path.resolve())

    def test_ask_vault_path_returns_none_when_cancelled(self) -> None:
        with patch('agileview_gui.filedialog.askdirectory', return_value=''):
            chosen = _ask_vault_path(parent=None, initial_dir=None)
        self.assertIsNone(chosen)

    def test_ask_vault_path_retries_after_invalid_folder(self) -> None:
        with TemporaryDirectory() as temp_dir:
            invalid = Path(temp_dir) / 'not-a-vault'
            valid = Path(temp_dir) / 'ok.opvault'
            invalid.mkdir()
            (valid / 'default').mkdir(parents=True)
            (valid / 'default' / 'profile.js').write_text('var profile={};', encoding='utf-8')

            with patch(
                'agileview_gui.filedialog.askdirectory',
                side_effect=[str(invalid), str(valid)],
            ), patch('agileview_gui.messagebox.showerror') as showerror:
                chosen = _ask_vault_path(parent=None, initial_dir=None)

            self.assertEqual(chosen, valid.resolve())
            showerror.assert_called_once()


class ConfigStateTests(unittest.TestCase):
    def test_show_secrets_defaults_to_false_when_not_set(self) -> None:
        with TemporaryDirectory() as temp_dir:
            app_dir = Path(temp_dir) / 'cfg'
            config_path = app_dir / 'config.json'
            with patch('agileview_gui.APP_DIR', app_dir), patch('agileview_gui.CONFIG_PATH', config_path):
                self.assertFalse(get_show_secrets_enabled())

    def test_show_secrets_roundtrip(self) -> None:
        with TemporaryDirectory() as temp_dir:
            app_dir = Path(temp_dir) / 'cfg'
            config_path = app_dir / 'config.json'
            with patch('agileview_gui.APP_DIR', app_dir), patch('agileview_gui.CONFIG_PATH', config_path):
                set_show_secrets_enabled(True)
                self.assertTrue(get_show_secrets_enabled())
                set_show_secrets_enabled(False)
                self.assertFalse(get_show_secrets_enabled())


if __name__ == '__main__':
    unittest.main()
