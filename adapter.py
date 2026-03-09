from __future__ import annotations

import contextlib
import getpass
import json
import os
import re
import shutil
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


class AgileViewError(Exception):
    """Base error for the viewer."""


class BackendUnavailableError(AgileViewError):
    """Raised when the onepasswordpy backend is not installed."""


@dataclass(slots=True)
class VaultItem:
    uuid: str
    title: str
    raw_item: Any


CATEGORY_LABELS: dict[str, str] = {
    'webforms.webform': 'Веб-логины',
    'securenotes.securenote': 'Защищённые заметки',
    'wallet.computer.license': 'Лицензии',
    'wallet.onlineservices.email': 'Учётные записи эл. почты',
    'wallet.financial.creditcard': 'Банковские карты',
    'wallet.government.socialsecuritynumber': 'Номера соц. страхования',
    'wallet.government.driverslicense': 'Водительские права',
    'wallet.government.passport': 'Паспорта',
    'wallet.membership.membership': 'Членства',
    'wallet.membership.rewards': 'Бонусные карты',
    'wallet.identity': 'Личные данные',
    'identities.identity': 'Личные данные',
    'wallet.password': 'Пароли',
    'wallet.bankaccount.us': 'Банковские счета',
    'wallet.bankaccount': 'Банковские счета',
    'wallet.database': 'Базы данных',
    'wallet.server': 'Серверы',
    'wallet.router': 'Роутеры',
    'wallet.outdoorlicense': 'Лицензии',
}

NON_EMPTY_VALUE = object()
_MISSING = object()
CUSTOM_CATEGORY_RULES: list[tuple[str, str, str, Any]] = [
    ('legacy.license', 'Лицензии', 'sections[1].title', 'Покупатель'),
    ('legacy.email_account', 'Учетные записи почты', 'sections[1].title', 'SMTP'),
    ('legacy.credit_card', 'Кредитные карты', 'cardholder', 'Контактная информация'),
    ('legacy.credit_card', 'Кредитные карты', 'sections[1].title', 'Контактная информация'),
    ('legacy.server', 'Серверы', 'sections[1].title', 'Консоль администрирования'),
    ('legacy.ssn', 'Номера социального страхования', 'sections[0].fields[1].a.generate', 'off'),
    ('legacy.router', 'Беспроводные маршрутизаторы', 'sections[0].fields[4].n', 'network_name'),
    ('legacy.driver_license', 'Водительские права', 'fullname', NON_EMPTY_VALUE),
    ('legacy.secure_note', 'Защищенные заметки', 'notesPlain', NON_EMPTY_VALUE),
]


class AgileKeychainBackend:
    """Thin adapter around onepasswordpy keychain APIs."""

    def __init__(self, bundle_path: str | os.PathLike[str]):
        self.bundle_path = str(bundle_path)
        self._keychain = None
        self._items: list[VaultItem] = []

    def unlock(self, master_password: str) -> None:
        AKeychain, CKeychain = _import_keychain_classes()
        keychain = None
        first_error: Exception | None = None

        for keychain_class in _keychain_candidates(self.bundle_path, AKeychain, CKeychain):
            try:
                candidate = keychain_class(self.bundle_path)
                candidate.unlock(master_password)
                keychain = candidate
                break
            except Exception as exc:
                if first_error is None:
                    first_error = exc

        if keychain is None:
            assert first_error is not None
            raise first_error

        items: list[VaultItem] = []
        for item in getattr(keychain, 'items', []):
            items.append(
                VaultItem(
                    uuid=getattr(item, 'uuid', ''),
                    title=getattr(item, 'title', '') or '(без названия)',
                    raw_item=item,
                )
            )

        self._keychain = keychain
        self._items = sorted(items, key=lambda i: ((i.title or '').casefold(), i.uuid.casefold()))

    @property
    def items(self) -> list[VaultItem]:
        return self._items

    def decrypt_item(self, item: VaultItem) -> dict[str, Any]:
        data = item.raw_item.decrypt()
        if not isinstance(data, dict):
            raise AgileViewError(f'Неожиданный формат данных у элемента {item.title!r}')
        return data


def _bootstrap_local_venv_site_packages() -> None:
    base_dir = Path(__file__).resolve().parent
    lib_dir = base_dir / '.venv' / 'lib'
    if not lib_dir.exists():
        return
    for site_packages_dir in sorted(lib_dir.glob('python*/site-packages')):
        if site_packages_dir.is_dir():
            site_packages = str(site_packages_dir)
            if site_packages not in sys.path:
                sys.path.insert(0, site_packages)


def _detect_keychain_format(bundle_path: str | os.PathLike[str]) -> str | None:
    bundle = Path(bundle_path)
    if (bundle / 'data' / 'default' / 'encryptionKeys.js').is_file():
        return 'agilekeychain'
    if (bundle / 'default' / 'profile.js').is_file():
        return 'opvault'

    suffix = bundle.suffix.casefold()
    if suffix == '.agilekeychain':
        return 'agilekeychain'
    if suffix in {'.opvault', '.cloudkeychain'}:
        return 'opvault'
    return None


def _find_child_vaults(parent: Path) -> list[Path]:
    if not parent.is_dir():
        return []
    candidates: list[Path] = []
    for child in sorted(parent.iterdir()):
        if not child.is_dir():
            continue
        if _detect_keychain_format(child) is not None:
            candidates.append(child)
    return candidates


def normalize_vault_path(path: str | os.PathLike[str]) -> Path:
    expanded = Path(path).expanduser()
    normalized = Path(os.path.abspath(str(expanded)))

    if not normalized.exists():
        return normalized

    if _detect_keychain_format(normalized) is not None:
        return normalized

    child_vaults = _find_child_vaults(normalized)
    if len(child_vaults) == 1:
        return child_vaults[0]
    if len(child_vaults) > 1:
        options = '\n'.join(f'- {candidate}' for candidate in child_vaults[:20])
        raise AgileViewError(
            'В выбранной папке найдено несколько vault. Выбери конкретный каталог vault:\n' + options
        )

    if normalized.is_dir():
        raise AgileViewError(
            'Выбранная папка не похожа на vault. Выбери каталог вида '
            '*.agilekeychain, *.opvault или *.cloudkeychain'
        )
    return normalized


def _keychain_candidates(bundle_path: str | os.PathLike[str], a_keychain: Any, c_keychain: Any) -> list[Any]:
    detected_format = _detect_keychain_format(bundle_path)
    if detected_format == 'opvault':
        return [c_keychain, a_keychain]
    return [a_keychain, c_keychain]


def _import_keychain_classes():
    try:
        from onepassword.keychain import AKeychain, CKeychain
        return AKeychain, CKeychain
    except Exception:
        _bootstrap_local_venv_site_packages()
        try:
            from onepassword.keychain import AKeychain, CKeychain
            return AKeychain, CKeychain
        except Exception as exc:  # pragma: no cover - depends on user env
            raise BackendUnavailableError(
                'Не удалось импортировать onepasswordpy. Установи зависимость: '
                'pip install git+https://github.com/Roguelazer/onepasswordpy.git'
            ) from exc


class VaultReader:
    def __init__(self, path: str | os.PathLike[str]):
        self.original_path = normalize_vault_path(path)
        self.snapshot_path: Path | None = None
        self.backend: AgileKeychainBackend | None = None

    def unlock(self, master_password: str) -> None:
        if not self.original_path.exists():
            raise FileNotFoundError(f'Vault не найден: {self.original_path}')

        with snapshot_bundle(self.original_path) as snap:
            backend = AgileKeychainBackend(snap)
            backend.unlock(master_password)
            self.snapshot_path = Path(snap)
            self.backend = backend

    def list_items(self) -> list[VaultItem]:
        self._ensure_unlocked()
        assert self.backend is not None
        return list(self.backend.items)

    def search(self, query: str, deep: bool = False) -> list[VaultItem]:
        self._ensure_unlocked()
        assert self.backend is not None
        needle = query.casefold()
        matches: list[VaultItem] = []
        for item in self.backend.items:
            if needle in item.title.casefold() or needle in item.uuid.casefold():
                matches.append(item)
                continue
            if deep:
                try:
                    payload = self.backend.decrypt_item(item)
                except Exception:
                    continue
                blob = json.dumps(payload, ensure_ascii=False).casefold()
                if needle in blob:
                    matches.append(item)
        return matches

    def resolve(self, selector: str) -> VaultItem:
        self._ensure_unlocked()
        assert self.backend is not None
        items = self.backend.items

        for item in items:
            if item.uuid == selector:
                return item

        exact = [i for i in items if i.title.casefold() == selector.casefold()]
        if len(exact) == 1:
            return exact[0]
        if len(exact) > 1:
            raise AgileViewError(
                'Найдено несколько записей с одинаковым title. Используй UUID:\n'
                + '\n'.join(f'- {i.uuid}  {i.title}' for i in exact)
            )

        fuzzy = [i for i in items if selector.casefold() in i.title.casefold()]
        if len(fuzzy) == 1:
            return fuzzy[0]
        if not fuzzy:
            raise AgileViewError(f'Запись не найдена: {selector!r}')
        raise AgileViewError(
            'Запрос слишком неоднозначный. Подходящие записи:\n'
            + '\n'.join(f'- {i.uuid}  {i.title}' for i in fuzzy[:20])
        )

    def decrypted_payload(self, selector: str) -> dict[str, Any]:
        item = self.resolve(selector)
        assert self.backend is not None
        return self.backend.decrypt_item(item)

    def _ensure_unlocked(self) -> None:
        if self.backend is None:
            raise AgileViewError('Vault ещё не разблокирован')


@contextlib.contextmanager
def snapshot_bundle(source: str | os.PathLike[str]):
    """Create a temporary snapshot of the bundle so Dropbox doesn't mutate it mid-read."""
    source_path = Path(source)
    temp_dir = tempfile.mkdtemp(prefix='agileview-')
    destination = Path(temp_dir) / source_path.name
    try:
        shutil.copytree(source_path, destination)
        yield str(destination)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


SECRET_KEY_RE = re.compile(r'(?:pass|secret|token|otp|cvv|pin|key)', re.IGNORECASE)
SECRET_FIELD_TYPE_MARKERS = {'P'}
SECRET_FIELD_NAME_MARKERS = {
    'password',
    'pin',
    'otp',
    'token',
    'secret',
    'cvv',
    'key',
    'license key',
    'registration code',
    'reg code',
    'product key',
}


def mask_secret_text(value: str) -> str:
    if not value:
        return ''
    return '•' * min(len(value), 12) + f' ({len(value)} chars)'


def mask_value(key: str, value: Any) -> Any:
    if not isinstance(value, str):
        return value
    if SECRET_KEY_RE.search(key):
        return mask_secret_text(value)
    return value


def looks_like_secret_field(field: dict[str, Any]) -> bool:
    designation = str(field.get('designation', '')).strip().casefold()
    name = str(field.get('name', '')).strip().casefold()
    field_type = str(field.get('type', '')).strip().upper()
    if field_type in SECRET_FIELD_TYPE_MARKERS:
        return True
    if designation in SECRET_FIELD_NAME_MARKERS or name in SECRET_FIELD_NAME_MARKERS:
        return True
    if SECRET_KEY_RE.search(designation) or SECRET_KEY_RE.search(name):
        return True
    return False


def _sanitize_payload(data: Any, parent_key: str | None = None) -> Any:
    if isinstance(data, dict):
        normalized_parent = (parent_key or '').casefold()
        in_secret_field = normalized_parent == 'fields' and looks_like_secret_field(data)
        result: dict[str, Any] = {}
        for key, value in data.items():
            key_text = str(key)
            normalized_key = key_text.casefold()
            masked_value = mask_value(key_text, value)
            if in_secret_field and normalized_key == 'value' and isinstance(masked_value, str):
                masked_value = mask_secret_text(masked_value)
            result[key_text] = _sanitize_payload(masked_value, normalized_key)
        return result
    if isinstance(data, list):
        return [_sanitize_payload(value, parent_key) for value in data]
    return data



def sanitize_payload(data: Any) -> Any:
    return _sanitize_payload(data)



def flatten_common_fields(data: dict[str, Any]) -> dict[str, Any]:
    """Best-effort extraction of common login-ish fields from decrypted JSON."""
    result: dict[str, Any] = {}

    def walk(obj: Any) -> Iterable[tuple[str, Any]]:
        if isinstance(obj, dict):
            for key, value in obj.items():
                yield key, value
                yield from walk(value)
        elif isinstance(obj, list):
            for value in obj:
                yield from walk(value)

    found_fields: dict[str, list[Any]] = {}
    for key, value in walk(data):
        lowered = str(key).casefold()
        if lowered in {
            'title', 'location', 'notesplain', 'url', 'username', 'password', 'email', 'hostname',
            'serial', 'license', 'key', 'registration code', 'license key', 'serial number', 'product key'
        }:
            found_fields.setdefault(lowered, []).append(value)

    for field in data.get('fields', []) if isinstance(data.get('fields'), list) else []:
        if not isinstance(field, dict):
            continue
        designation = str(field.get('designation', '')).casefold()
        name = str(field.get('name', '')).casefold()
        field_type = str(field.get('type', '')).strip().upper()
        value = field.get('value')
        if designation == 'password' or name == 'password' or field_type == 'P':
            found_fields.setdefault('password', []).append(value)
        if designation in {'username', 'email'} or name in {'username', 'email', 'login'}:
            found_fields.setdefault('username', []).append(value)
        if name in {'serial', 'serial number'}:
            found_fields.setdefault('serial', []).append(value)
        if name in {'license', 'license key', 'registration code', 'reg code', 'product key', 'key'}:
            found_fields.setdefault('license key', []).append(value)

    for key in (
        'title', 'username', 'password', 'url', 'location', 'notesplain', 'email', 'hostname',
        'serial', 'license', 'license key', 'registration code', 'product key', 'key', 'serial number'
    ):
        values = [v for v in found_fields.get(key, []) if v not in (None, '')]
        if values:
            result[key] = values[0]

    return result



def first_non_empty(*values: Any) -> str | None:
    for value in values:
        if isinstance(value, str):
            text = value.strip()
            if text:
                return text
    return None



def infer_type_name(data: dict[str, Any]) -> str:
    direct_candidates = [
        data.get('typeName'),
        data.get('type'),
        data.get('category'),
        data.get('categoryName'),
    ]
    nested = data.get('secureContents')
    if isinstance(nested, dict):
        direct_candidates.extend([
            nested.get('typeName'),
            nested.get('type'),
            nested.get('category'),
            nested.get('categoryName'),
        ])
    value = first_non_empty(*direct_candidates)
    return value or 'unknown'



def category_label_from_type(type_name: str) -> str:
    normalized = (type_name or 'unknown').strip().casefold()
    if normalized in CATEGORY_LABELS:
        return CATEGORY_LABELS[normalized]
    tail = normalized.split('.')[-1]
    if tail in {'mc', 'visa'}:
        return 'Кредитные карты'
    if tail == 'unknown':
        return 'Без категории'
    pretty = tail.replace('_', ' ').replace('-', ' ')
    return pretty[:1].upper() + pretty[1:]



def has_legacy_login_field_pattern(data: dict[str, Any]) -> bool:
    fields = data.get('fields')
    if not isinstance(fields, list) or len(fields) < 2:
        return False
    first, second = fields[0], fields[1]
    if not isinstance(first, dict) or not isinstance(second, dict):
        return False
    first_type = str(first.get('type', '')).strip().upper()
    second_type = str(second.get('type', '')).strip().upper()
    return first_type in {'T', 'P'} and second_type in {'T', 'P'}



def _path_tokens(path: str) -> list[str | int]:
    tokens: list[str | int] = []
    for key_token, index_token in re.findall(r'([^\.\[\]]+)|\[(\d+)\]', path):
        if key_token:
            tokens.append(key_token)
        elif index_token:
            tokens.append(int(index_token))
    return tokens


def _value_by_path(data: Any, path: str) -> Any:
    current = data
    for token in _path_tokens(path):
        if isinstance(token, int):
            if not isinstance(current, list) or token < 0 or token >= len(current):
                return _MISSING
            current = current[token]
            continue
        if not isinstance(current, dict) or token not in current:
            return _MISSING
        current = current[token]
    return current


def _matches_expected_value(actual: Any, expected: Any) -> bool:
    if actual is _MISSING:
        return False
    if expected is NON_EMPTY_VALUE:
        if isinstance(actual, str):
            return bool(actual.strip())
        return actual is not None
    if isinstance(expected, str):
        return str(actual).strip().casefold() == expected.strip().casefold()
    return actual == expected


def custom_category_for_payload(data: dict[str, Any]) -> tuple[str, str] | None:
    for type_name, label, path, expected in CUSTOM_CATEGORY_RULES:
        actual = _value_by_path(data, path)
        if _matches_expected_value(actual, expected):
            return type_name, label
    return None


def category_for_payload(data: dict[str, Any]) -> tuple[str, str]:
    custom = custom_category_for_payload(data)
    if custom is not None:
        return custom
    if has_legacy_login_field_pattern(data):
        return 'legacy.login', 'Логины'
    type_name = infer_type_name(data)
    return type_name, category_label_from_type(type_name)



def read_master_password(stdin: bool = False) -> str:
    if stdin:
        value = os.sys.stdin.readline().rstrip('\n')
        if not value:
            raise AgileViewError('Из stdin пришёл пустой master password')
        return value

    env_value = os.environ.get('AGILEVIEW_MASTER_PASSWORD')
    if env_value:
        return env_value

    value = getpass.getpass('Master password: ')
    if not value:
        raise AgileViewError('Master password пустой')
    return value
