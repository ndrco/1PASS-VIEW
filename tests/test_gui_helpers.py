from __future__ import annotations

import unittest

from adapter import flatten_common_fields, sanitize_payload
from agileview_gui import combine_field_rows, flatten_for_table, pick_quick_fields, unlock_with_password_fallback


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


if __name__ == '__main__':
    unittest.main()
