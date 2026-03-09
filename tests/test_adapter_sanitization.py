from __future__ import annotations

import json
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from adapter import (
    AgileViewError,
    AgileKeychainBackend,
    VaultItem,
    _detect_keychain_format,
    _keychain_candidates,
    category_for_payload,
    category_label_from_type,
    flatten_common_fields,
    normalize_vault_path,
    sanitize_payload,
)


class SanitizePayloadTests(unittest.TestCase):
    def test_masks_secret_value_inside_fields_entry(self) -> None:
        payload = {
            'fields': [
                {'designation': 'password', 'name': 'password', 'type': 'P', 'value': 'abc123'},
                {'designation': 'username', 'name': 'username', 'type': 'T', 'value': 'alice'},
            ]
        }

        sanitized = sanitize_payload(payload)

        self.assertNotEqual(sanitized['fields'][0]['value'], 'abc123')
        self.assertEqual(sanitized['fields'][1]['value'], 'alice')
        self.assertNotIn('abc123', json.dumps(sanitized, ensure_ascii=False))

    def test_masks_secret_value_by_field_name(self) -> None:
        payload = {'fields': [{'designation': '', 'name': 'token', 'type': 'T', 'value': 'secret-token'}]}

        sanitized = sanitize_payload(payload)

        self.assertNotEqual(sanitized['fields'][0]['value'], 'secret-token')

    def test_flatten_common_fields_recognizes_type_p_as_password(self) -> None:
        payload = {'fields': [{'type': 'P', 'value': 'abc123'}]}

        compact = flatten_common_fields(payload)

        self.assertEqual(compact.get('password'), 'abc123')

    def test_backend_exposes_items_property_and_decrypt_item(self) -> None:
        backend = AgileKeychainBackend('/tmp/fake.agilekeychain')
        backend._items = [VaultItem(uuid='1', title='Entry', raw_item=SimpleNamespace(decrypt=lambda: {'ok': True}))]

        self.assertEqual(len(backend.items), 1)
        self.assertEqual(backend.decrypt_item(backend.items[0]), {'ok': True})

    def test_detect_keychain_format_agile(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / 'vault.agilekeychain'
            (root / 'data' / 'default').mkdir(parents=True)
            (root / 'data' / 'default' / 'encryptionKeys.js').write_text('{}', encoding='utf-8')

            self.assertEqual(_detect_keychain_format(root), 'agilekeychain')

    def test_detect_keychain_format_opvault(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / 'vault.opvault'
            (root / 'default').mkdir(parents=True)
            (root / 'default' / 'profile.js').write_text('var profile={};', encoding='utf-8')

            self.assertEqual(_detect_keychain_format(root), 'opvault')

    def test_keychain_candidates_prioritize_opvault_backend(self) -> None:
        candidates = _keychain_candidates('/tmp/vault.opvault', 'A', 'C')
        self.assertEqual(candidates, ['C', 'A'])

    def test_unlock_prefers_opvault_backend_when_path_matches(self) -> None:
        calls: list[str] = []

        class FakeAKeychain:
            def __init__(self, path: str):
                calls.append('A:init')

            def unlock(self, password: str) -> None:
                calls.append('A:unlock')
                raise AssertionError('AKeychain should not be used first for .opvault')

        class FakeCKeychain:
            def __init__(self, path: str):
                calls.append('C:init')
                self.items = [SimpleNamespace(uuid='u1', title='Entry', decrypt=lambda: {'ok': True})]

            def unlock(self, password: str) -> None:
                calls.append('C:unlock')

        backend = AgileKeychainBackend('/tmp/vault.opvault')
        with patch('adapter._import_keychain_classes', return_value=(FakeAKeychain, FakeCKeychain)):
            backend.unlock('master')

        self.assertEqual(calls[:2], ['C:init', 'C:unlock'])
        self.assertEqual(len(backend.items), 1)

    def test_unlock_raises_when_all_keychain_backends_fail(self) -> None:
        class FakeAKeychain:
            def __init__(self, path: str):
                self.items = []

            def unlock(self, password: str) -> None:
                raise RuntimeError('a-failed')

        class FakeCKeychain:
            def __init__(self, path: str):
                self.items = []

            def unlock(self, password: str) -> None:
                raise RuntimeError('c-failed')

        backend = AgileKeychainBackend('/tmp/vault.opvault')
        with patch('adapter._import_keychain_classes', return_value=(FakeAKeychain, FakeCKeychain)):
            with self.assertRaises(RuntimeError) as ctx:
                backend.unlock('master')

        self.assertEqual(str(ctx.exception), 'c-failed')

    def test_normalize_vault_path_detects_single_child_vault(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            parent = Path(temp_dir) / '1Password'
            vault = parent / '1Password.opvault'
            (vault / 'default').mkdir(parents=True)
            (vault / 'default' / 'profile.js').write_text('var profile={};', encoding='utf-8')

            normalized = normalize_vault_path(parent)
            self.assertEqual(normalized, vault.resolve())

    def test_normalize_vault_path_raises_when_multiple_child_vaults(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            parent = Path(temp_dir) / 'vaults'
            first = parent / 'a.opvault'
            second = parent / 'b.opvault'
            (first / 'default').mkdir(parents=True)
            (second / 'default').mkdir(parents=True)
            (first / 'default' / 'profile.js').write_text('var profile={};', encoding='utf-8')
            (second / 'default' / 'profile.js').write_text('var profile={};', encoding='utf-8')

            with self.assertRaises(AgileViewError):
                normalize_vault_path(parent)

    def test_normalize_vault_path_raises_for_non_vault_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            folder = Path(temp_dir) / 'random-folder'
            folder.mkdir()

            with self.assertRaises(AgileViewError):
                normalize_vault_path(folder)

    def test_custom_category_rules(self) -> None:
        cases = [
            (
                {'sections': [{}, {'title': 'Покупатель'}]},
                ('legacy.license', 'Лицензии'),
            ),
            (
                {'sections': [{}, {'title': 'SMTP'}]},
                ('legacy.email_account', 'Учетные записи почты'),
            ),
            (
                {'cardholder': 'Контактная информация'},
                ('legacy.credit_card', 'Кредитные карты'),
            ),
            (
                {'sections': [{}, {'title': 'Контактная информация'}]},
                ('legacy.credit_card', 'Кредитные карты'),
            ),
            (
                {'sections': [{}, {'title': 'Консоль администрирования'}]},
                ('legacy.server', 'Серверы'),
            ),
            (
                {'sections': [{'fields': [{}, {'a': {'generate': 'off'}}]}]},
                ('legacy.ssn', 'Номера социального страхования'),
            ),
            (
                {'sections': [{'fields': [{}, {}, {}, {}, {'n': 'network_name'}]}]},
                ('legacy.router', 'Беспроводные маршрутизаторы'),
            ),
            (
                {'notesPlain': 'any non-empty note'},
                ('legacy.secure_note', 'Защищенные заметки'),
            ),
            (
                {'fullname': 'John Doe'},
                ('legacy.driver_license', 'Водительские права'),
            ),
        ]

        for payload, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(category_for_payload(payload), expected)

    def test_custom_rules_have_priority_over_legacy_login_pattern(self) -> None:
        payload = {
            'fields': [{'type': 'T'}, {'type': 'P'}],
            'cardholder': 'Контактная информация',
        }
        self.assertEqual(category_for_payload(payload), ('legacy.credit_card', 'Кредитные карты'))

    def test_mc_and_visa_type_names_map_to_credit_cards(self) -> None:
        self.assertEqual(category_label_from_type('mc'), 'Кредитные карты')
        self.assertEqual(category_label_from_type('visa'), 'Кредитные карты')


if __name__ == '__main__':
    unittest.main()
