from __future__ import annotations

import json
from types import SimpleNamespace
import unittest

from adapter import AgileKeychainBackend, VaultItem, flatten_common_fields, sanitize_payload


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


if __name__ == '__main__':
    unittest.main()
