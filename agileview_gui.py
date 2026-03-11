from __future__ import annotations

import argparse
import json
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
from adapter import (
    AgileViewError,
    VaultItem,
    VaultReader,
    category_for_payload,
    flatten_common_fields,
    normalize_vault_path,
    sanitize_payload,
)

APP_NAME = '1Pass-view'
APP_CLASS = '1PassView'
APP_DIR = Path.home() / '.config' / 'agileview'
CONFIG_PATH = APP_DIR / 'config.json'
BASE_DIR = Path(__file__).resolve().parent
ICON_CANDIDATES = [
    BASE_DIR / 'assets' / '1pass-view.png',
    BASE_DIR / 'assets' / '1pass-view-256.png',
    BASE_DIR / '1pass-view.png',
]

QUICK_COPY_SPECS: list[tuple[str, str, tuple[str, ...]]] = [
    ('username', 'Копировать username', ('username', 'email', 'login')),
    ('password', 'Копировать password', ('password',)),
    ('serial', 'Копировать serial', ('serial', 'serial number')),
    (
        'license_key',
        'Копировать license/key',
        ('license', 'license key', 'registration code', 'reg code', 'serial number', 'product key', 'key'),
    ),
]

PREFERRED_FIELD_ORDER = {
    'title': 0,
    'username': 1,
    'email': 2,
    'password': 3,
    'url': 4,
    'hostname': 5,
    'location': 6,
    'notesplain': 7,
    'serial': 8,
    'license': 9,
    'license key': 10,
    'registration code': 11,
    'product key': 12,
    'key': 13,
}

SKIP_PATHS = {
    'title',
    'uuid',
    'type',
    'typename',
    'category',
    'categoryname',
}


@dataclass(slots=True)
class DisplayItem:
    item: VaultItem
    type_name: str
    category_label: str


@dataclass(slots=True, frozen=True)
class FlatTableRow:
    path: str
    field: str
    value: str


@dataclass(slots=True, frozen=True)
class FieldTableRow:
    field: str
    display_value: str
    copy_value: str


@dataclass(slots=True)
class UnlockWithFallbackResult:
    success: bool
    password: str
    first_error: Exception | None = None
    second_error: Exception | None = None
    prompted: bool = False
    cancelled: bool = False


def resolve_icon_path() -> Path | None:
    for path in ICON_CANDIDATES:
        if path.exists():
            return path
    return None


class WindowIdentityMixin:
    def _apply_app_identity(self) -> None:
        self.title(APP_NAME)
        try:
            self.iconname(APP_NAME)
        except tk.TclError:
            pass
        try:
            self.wm_class('1pass-view', APP_CLASS)
        except Exception:
            pass
        icon_path = resolve_icon_path()
        self._icon_image = None
        if icon_path is not None:
            try:
                self._icon_image = tk.PhotoImage(file=str(icon_path))
                self.iconphoto(True, self._icon_image)
            except tk.TclError:
                self._icon_image = None


class AgileViewGUI(WindowIdentityMixin, tk.Tk):
    def __init__(self, reader: VaultReader, items: list[VaultItem], master_password: str):
        super().__init__(className=APP_CLASS)
        self.reader = reader
        self.all_items = items
        self.master_password = master_password
        self.payload_cache: dict[str, dict[str, Any]] = {}
        self.search_blob_by_uuid: dict[str, str] = {}
        self.display_items: list[DisplayItem] = []
        self.items_by_uuid: dict[str, DisplayItem] = {}
        self.filtered_items: list[DisplayItem] = []
        self.field_rows_by_iid: dict[str, FieldTableRow] = {}
        self.quick_fields: dict[str, str] = {}
        self.active_menu: tk.Menu | None = None

        self._apply_app_identity()
        self.geometry('1320x820')
        self.minsize(1020, 640)

        self.search_var = tk.StringVar()
        self.reveal_var = tk.BooleanVar(value=get_show_secrets_enabled())
        self.status_var = tk.StringVar(value=f'Загружено записей: {len(items)}')
        self.path_var = tk.StringVar(value=str(reader.original_path))

        self._build_ui()
        self._bind_events()
        self._build_display_index()
        self._populate_tree(self.display_items)
        self.after(50, self._focus_tree_first_item)

    def _build_ui(self) -> None:
        root = ttk.Frame(self, padding=10)
        root.pack(fill='both', expand=True)

        top = ttk.Frame(root)
        top.pack(fill='x')

        ttk.Label(top, text='Vault:').pack(side='left')
        path_entry = ttk.Entry(top, textvariable=self.path_var)
        path_entry.pack(side='left', fill='x', expand=True, padx=(6, 8))
        path_entry.state(['readonly'])
        self.change_vault_btn = ttk.Button(top, text='Сменить vault...', command=self._change_vault)
        self.change_vault_btn.pack(side='left')

        controls = ttk.Frame(root)
        controls.pack(fill='x', pady=(10, 6))

        ttk.Label(controls, text='Поиск:').pack(side='left')
        self.search_entry = ttk.Entry(controls, textvariable=self.search_var)
        self.search_entry.pack(side='left', fill='x', expand=True, padx=(6, 8))
        ttk.Label(controls, text='(title/uuid/поля/значения)').pack(side='left', padx=(0, 8))

        self.reveal_check = ttk.Checkbutton(
            controls,
            text='Показать секретные поля',
            variable=self.reveal_var,
            command=self._on_reveal_toggle,
        )
        self.reveal_check.pack(side='left')

        self.copy_btn = ttk.Button(controls, text='Копировать JSON', command=self._copy_json)
        self.copy_btn.pack(side='left', padx=(8, 0))

        self.reload_btn = ttk.Button(controls, text='Обновить', command=self._reload_list)
        self.reload_btn.pack(side='left', padx=(8, 0))

        quick = ttk.Frame(root)
        quick.pack(fill='x', pady=(0, 10))
        ttk.Label(quick, text='Быстрое копирование:').pack(side='left')

        self.quick_copy_buttons: dict[str, ttk.Button] = {}
        for field_key, label, _aliases in QUICK_COPY_SPECS:
            btn = ttk.Button(
                quick,
                text=label,
                command=lambda key=field_key: self._copy_quick_field(key),
                state='disabled',
            )
            btn.pack(side='left', padx=(8, 0))
            self.quick_copy_buttons[field_key] = btn

        paned = ttk.Panedwindow(root, orient='horizontal')
        paned.pack(fill='both', expand=True)

        left = ttk.Frame(paned, padding=(0, 0, 8, 0))
        right = ttk.Frame(paned)
        paned.add(left, weight=1)
        paned.add(right, weight=3)

        self.tree = ttk.Treeview(left, columns=('uuid',), show='tree headings', selectmode='browse')
        self.tree.heading('#0', text='Категория / запись')
        self.tree.heading('uuid', text='UUID')
        self.tree.column('#0', width=340, anchor='w')
        self.tree.column('uuid', width=270, anchor='w')

        tree_scroll_y = ttk.Scrollbar(left, orient='vertical', command=self.tree.yview)
        tree_scroll_x = ttk.Scrollbar(left, orient='horizontal', command=self.tree.xview)
        self.tree.configure(yscrollcommand=tree_scroll_y.set, xscrollcommand=tree_scroll_x.set)

        self.tree.grid(row=0, column=0, sticky='nsew')
        tree_scroll_y.grid(row=0, column=1, sticky='ns')
        tree_scroll_x.grid(row=1, column=0, sticky='ew')
        left.rowconfigure(0, weight=1)
        left.columnconfigure(0, weight=1)

        self.notebook = ttk.Notebook(right)
        self.notebook.pack(fill='both', expand=True)

        fields_tab = ttk.Frame(self.notebook)
        json_tab = ttk.Frame(self.notebook)
        self.notebook.add(fields_tab, text='Поля')
        self.notebook.add(json_tab, text='JSON')

        fields_pane = ttk.Panedwindow(fields_tab, orient='vertical')
        fields_pane.pack(fill='both', expand=True)

        fields_table_wrap = ttk.Frame(fields_pane)
        fields_notes_wrap = ttk.LabelFrame(fields_pane, text='notesPlain')
        fields_pane.add(fields_table_wrap, weight=5)
        fields_pane.add(fields_notes_wrap, weight=1)

        self.fields_tree = ttk.Treeview(fields_table_wrap, columns=('field', 'value'), show='headings', selectmode='browse')
        self.fields_tree.heading('field', text='Поле')
        self.fields_tree.heading('value', text='Значение')
        self.fields_tree.column('field', width=300, anchor='w')
        self.fields_tree.column('value', width=760, anchor='w')

        fields_scroll_y = ttk.Scrollbar(fields_table_wrap, orient='vertical', command=self.fields_tree.yview)
        fields_scroll_x = ttk.Scrollbar(fields_table_wrap, orient='horizontal', command=self.fields_tree.xview)
        self.fields_tree.configure(yscrollcommand=fields_scroll_y.set, xscrollcommand=fields_scroll_x.set)

        self.fields_tree.grid(row=0, column=0, sticky='nsew')
        fields_scroll_y.grid(row=0, column=1, sticky='ns')
        fields_scroll_x.grid(row=1, column=0, sticky='ew')
        fields_table_wrap.rowconfigure(0, weight=1)
        fields_table_wrap.columnconfigure(0, weight=1)

        self.notes_text = tk.Text(fields_notes_wrap, wrap='none', font=('TkFixedFont', 10), height=5)
        notes_scroll_y = ttk.Scrollbar(fields_notes_wrap, orient='vertical', command=self.notes_text.yview)
        notes_scroll_x = ttk.Scrollbar(fields_notes_wrap, orient='horizontal', command=self.notes_text.xview)
        self.notes_text.configure(yscrollcommand=notes_scroll_y.set, xscrollcommand=notes_scroll_x.set)
        self.notes_text.grid(row=0, column=0, sticky='nsew')
        notes_scroll_y.grid(row=0, column=1, sticky='ns')
        notes_scroll_x.grid(row=1, column=0, sticky='ew')
        fields_notes_wrap.rowconfigure(0, weight=1)
        fields_notes_wrap.columnconfigure(0, weight=1)

        self.json_text = tk.Text(json_tab, wrap='none', font=('TkFixedFont', 10))
        json_scroll_y = ttk.Scrollbar(json_tab, orient='vertical', command=self.json_text.yview)
        json_scroll_x = ttk.Scrollbar(json_tab, orient='horizontal', command=self.json_text.xview)
        self.json_text.configure(yscrollcommand=json_scroll_y.set, xscrollcommand=json_scroll_x.set)
        self.json_text.grid(row=0, column=0, sticky='nsew')
        json_scroll_y.grid(row=0, column=1, sticky='ns')
        json_scroll_x.grid(row=1, column=0, sticky='ew')
        json_tab.rowconfigure(0, weight=1)
        json_tab.columnconfigure(0, weight=1)
        self.json_text.configure(state='disabled')
        self._configure_readonly_text(self.notes_text)
        self._set_text(self.notes_text, '')

        status = ttk.Label(root, textvariable=self.status_var, anchor='w')
        status.pack(fill='x', pady=(8, 0))

        self.field_menu = tk.Menu(self, tearoff=0)
        self.field_menu.add_command(label='Копировать значение', command=self._copy_selected_field_value)
        self.field_menu.add_command(label='Копировать имя поля', command=self._copy_selected_field_name)
        self.field_menu.add_command(label='Копировать строку', command=self._copy_selected_field_row)

        self.json_menu = tk.Menu(self, tearoff=0)
        self.json_menu.add_command(label='Копировать выделенное', command=self._copy_selected_json_text)
        self.json_menu.add_command(label='Копировать весь JSON', command=self._copy_json)

        self.notes_menu = tk.Menu(self, tearoff=0)
        self.notes_menu.add_command(label='Копировать выделенное', command=self._copy_selected_notes_text)

    def _bind_events(self) -> None:
        self.search_var.trace_add('write', self._on_search_change)
        self.tree.bind('<<TreeviewSelect>>', lambda _event: self._display_current_selection())
        self.tree.bind('<Double-1>', self._on_tree_double_click)
        self.tree.bind('<Button-1>', lambda _event: self._hide_context_menu())

        self.fields_tree.bind('<Button-3>', self._show_field_context_menu)
        self.fields_tree.bind('<Double-1>', lambda _event: self._copy_selected_field_value())
        self.fields_tree.bind('<Control-c>', lambda _event: self._copy_selected_field_value())
        self.fields_tree.bind('<Motion>', self._hide_field_menu_on_empty_space)
        self.fields_tree.bind('<Button-1>', lambda _event: self._hide_context_menu())

        self.notes_text.bind('<Button-3>', self._show_notes_context_menu)
        self.notes_text.bind('<Control-c>', self._copy_selected_notes_text)
        self.notes_text.bind('<Button-1>', lambda _event: self._hide_context_menu())

        self.json_text.bind('<Button-3>', self._show_json_context_menu)
        self.json_text.bind('<Control-c>', self._copy_selected_json_text)
        self.json_text.bind('<Button-1>', lambda _event: self._hide_context_menu())

        self.bind('<Control-f>', self._focus_search)
        self.bind('<Control-o>', lambda _event: self._change_vault())
        self.bind('<F5>', lambda _event: self._reload_list())
        self.bind('<Escape>', lambda _event: self._hide_context_menu())
        self.bind('<Button-1>', lambda _event: self._hide_context_menu(), add='+')

    def _build_display_index(self) -> None:
        self.display_items.clear()
        self.items_by_uuid.clear()
        self.search_blob_by_uuid.clear()
        errors = 0
        for item in self.all_items:
            try:
                payload = self._get_payload(item.uuid)
                type_name, category_label = category_for_payload(payload)
                payload_search_blob = build_search_blob(payload)
            except Exception:
                errors += 1
                type_name, category_label = 'unknown', 'Без категории'
                payload_search_blob = ''
            display = DisplayItem(item=item, type_name=type_name, category_label=category_label)
            self.display_items.append(display)
            self.items_by_uuid[item.uuid] = display
            metadata_blob = ' '.join((item.title, item.uuid, category_label, type_name))
            self.search_blob_by_uuid[item.uuid] = f'{metadata_blob} {payload_search_blob}'.casefold()

        self.display_items.sort(key=lambda d: (d.category_label.casefold(), d.item.title.casefold(), d.item.uuid.casefold()))
        if errors:
            self.status_var.set(f'Загружено записей: {len(self.all_items)} (не удалось определить категорию у {errors})')
        else:
            self.status_var.set(f'Загружено записей: {len(self.all_items)}')

    def _focus_tree_first_item(self) -> None:
        first = self._first_item_iid()
        if not first:
            return
        self.tree.selection_set(first)
        self.tree.focus(first)
        self.tree.see(first)
        self._display_current_selection()

    def _first_item_iid(self) -> str | None:
        for category_iid in self.tree.get_children(''):
            children = self.tree.get_children(category_iid)
            if children:
                return children[0]
        return None

    def _focus_search(self, _event=None):
        self.search_entry.focus_set()
        self.search_entry.select_range(0, 'end')
        return 'break'

    def _populate_tree(self, items: list[DisplayItem]) -> None:
        current_uuid = self._selected_uuid()
        for row_id in self.tree.get_children():
            self.tree.delete(row_id)

        self.filtered_items = list(items)
        categories: dict[str, list[DisplayItem]] = {}
        for display in items:
            categories.setdefault(display.category_label, []).append(display)

        for category in sorted(categories, key=str.casefold):
            cat_iid = f'cat::{category}'
            self.tree.insert('', 'end', iid=cat_iid, text=f'{category} ({len(categories[category])})', values=('',), open=True)
            for display in categories[category]:
                item_iid = f'item::{display.item.uuid}'
                self.tree.insert(cat_iid, 'end', iid=item_iid, text=display.item.title, values=(display.item.uuid,))

        self.status_var.set(f'Показано записей: {len(items)} из {len(self.display_items)}')

        if current_uuid and current_uuid in self.items_by_uuid and any(d.item.uuid == current_uuid for d in items):
            iid = f'item::{current_uuid}'
            self.tree.selection_set(iid)
            self.tree.focus(iid)
            self.tree.see(iid)
        elif items:
            self._focus_tree_first_item()
        else:
            self._clear_fields_view('Ничего не найдено.')
            self._set_text(self.notes_text, '')
            self._set_text(self.json_text, '')
            self.quick_fields = {}
            self._update_quick_copy_buttons()

    def _on_search_change(self, *_args) -> None:
        query = self.search_var.get().strip().casefold()
        if not query:
            self._populate_tree(self.display_items)
            return

        filtered = [
            display
            for display in self.display_items
            if query in self.search_blob_by_uuid.get(display.item.uuid, '')
        ]
        self._populate_tree(filtered)

    def _reload_list(self) -> None:
        self._hide_context_menu()
        result = unlock_with_password_fallback(
            self.reader,
            self.master_password,
            lambda: _ask_password(parent=self),
        )
        if not result.success:
            if result.cancelled:
                self.status_var.set('Обновление отменено: мастер-пароль не введён')
                return
            if result.second_error is not None:
                message = (
                    'Не удалось обновить vault.\n\n'
                    f'Первая попытка: {result.first_error}\n'
                    f'Повторная попытка: {result.second_error}'
                )
            else:
                message = f'Не удалось обновить vault:\n{result.first_error}'
            messagebox.showerror(APP_NAME, message)
            self.status_var.set('Обновление не удалось')
            return

        self.master_password = result.password
        self.payload_cache.clear()
        self.all_items = self.reader.list_items()
        self._build_display_index()
        self._on_search_change()

    def _change_vault(self) -> None:
        self._hide_context_menu()
        initial_dir = str(self.reader.original_path.parent)
        new_path = _ask_vault_path(parent=self, initial_dir=initial_dir)
        if new_path is None:
            self.status_var.set('Смена vault отменена')
            return
        try:
            new_reader = VaultReader(new_path)
        except Exception as exc:
            messagebox.showerror(APP_NAME, f'Не удалось открыть выбранный vault:\n{exc}')
            self.status_var.set('Не удалось сменить vault')
            return
        if new_reader.original_path == self.reader.original_path:
            self.status_var.set('Текущий vault уже выбран')
            return
        result = unlock_with_password_fallback(
            new_reader,
            self.master_password,
            lambda: _ask_password(parent=self),
        )
        if not result.success:
            if result.cancelled:
                self.status_var.set('Смена vault отменена: мастер-пароль не введён')
                return
            if result.second_error is not None:
                message = (
                    'Не удалось открыть выбранный vault.\n\n'
                    f'Первая попытка: {result.first_error}\n'
                    f'Повторная попытка: {result.second_error}'
                )
            else:
                message = f'Не удалось открыть выбранный vault:\n{result.first_error}'
            messagebox.showerror(APP_NAME, message)
            self.status_var.set('Не удалось сменить vault')
            return

        self.reader = new_reader
        self.master_password = result.password
        set_last_vault_path(new_path)
        self.path_var.set(str(new_path))
        self.search_var.set('')
        self.payload_cache.clear()
        self.all_items = self.reader.list_items()
        self._build_display_index()
        self._on_search_change()

    def _selected_tree_iid(self) -> str | None:
        selected = self.tree.selection()
        return selected[0] if selected else None

    def _selected_uuid(self) -> str | None:
        iid = self._selected_tree_iid()
        if not iid or not iid.startswith('item::'):
            return None
        return iid.split('::', 1)[1]

    def _on_tree_double_click(self, _event=None) -> None:
        iid = self._selected_tree_iid()
        if not iid:
            return
        if iid.startswith('cat::'):
            self.tree.item(iid, open=not self.tree.item(iid, 'open'))
            return
        self._display_current_selection()

    def _get_payload(self, uuid: str) -> dict[str, Any]:
        if uuid not in self.payload_cache:
            self.payload_cache[uuid] = self.reader.decrypted_payload(uuid)
        return self.payload_cache[uuid]

    def _display_current_selection(self) -> None:
        uuid = self._selected_uuid()
        if not uuid:
            self._set_text(self.notes_text, '')
            self.quick_fields = {}
            self._update_quick_copy_buttons()
            return

        try:
            payload = self._get_payload(uuid)
            display = self.items_by_uuid.get(uuid)
            title = display.item.title if display else uuid
            reveal = self.reveal_var.get()

            compact_payload = flatten_common_fields(payload)
            rendered_payload = payload if reveal else sanitize_payload(payload)
            rendered_compact = compact_payload if reveal else sanitize_payload(compact_payload)
            category_label = display.category_label if display else 'Без категории'
            type_name = display.type_name if display else 'unknown'
            rendered_notes_plain = extract_notes_plain(payload)

            display_table_payload: dict[str, Any] = {
                'title': title,
                'uuid': uuid,
                'category': category_label,
                'typeName': type_name,
                **rendered_compact,
                **rendered_payload,
            }
            copy_table_payload: dict[str, Any] = {
                'title': title,
                'uuid': uuid,
                'category': category_label,
                'typeName': type_name,
                **compact_payload,
                **payload,
            }
            display_rows = flatten_for_table(display_table_payload)
            copy_rows = flatten_for_table(copy_table_payload)
            self._populate_fields_table(combine_field_rows(display_rows, copy_rows))
            self._set_text(self.notes_text, rendered_notes_plain)
            self._set_text(self.json_text, json.dumps(rendered_payload, ensure_ascii=False, indent=2))

            self.quick_fields = pick_quick_fields(copy_rows)
            self._update_quick_copy_buttons()
            self.status_var.set(f'Открыта запись: {title}')
        except Exception as exc:
            self._clear_fields_view(f'Ошибка чтения записи: {exc}')
            self._set_text(self.notes_text, '')
            self._set_text(self.json_text, traceback.format_exc())
            self.quick_fields = {}
            self._update_quick_copy_buttons()
            self.status_var.set('Ошибка чтения записи')

    def _populate_fields_table(self, rows: list[FieldTableRow]) -> None:
        for row_id in self.fields_tree.get_children():
            self.fields_tree.delete(row_id)
        self.field_rows_by_iid.clear()

        if not rows:
            self._clear_fields_view('Полей не найдено.')
            return

        for index, row in enumerate(rows):
            iid = f'field::{index}'
            self.fields_tree.insert('', 'end', iid=iid, values=(row.field, row.display_value))
            self.field_rows_by_iid[iid] = row

        first = self.fields_tree.get_children()
        if first:
            self.fields_tree.selection_set(first[0])
            self.fields_tree.focus(first[0])
            self.fields_tree.see(first[0])

    def _clear_fields_view(self, message: str) -> None:
        for row_id in self.fields_tree.get_children():
            self.fields_tree.delete(row_id)
        self.field_rows_by_iid.clear()
        iid = 'message'
        self.fields_tree.insert('', 'end', iid=iid, values=('Статус', message))
        self.field_rows_by_iid[iid] = FieldTableRow(field='Статус', display_value=message, copy_value=message)

    def _refresh_details(self) -> None:
        self._display_current_selection()

    def _on_reveal_toggle(self) -> None:
        set_show_secrets_enabled(self.reveal_var.get())
        self._refresh_details()

    def _show_field_context_menu(self, event) -> None:
        row_id = self.fields_tree.identify_row(event.y)
        if row_id:
            self.fields_tree.selection_set(row_id)
            self.fields_tree.focus(row_id)
        self._hide_context_menu()
        self.active_menu = self.field_menu
        self.field_menu.post(event.x_root, event.y_root)

    def _show_json_context_menu(self, event) -> None:
        self.json_text.focus_set()
        self._hide_context_menu()
        self.active_menu = self.json_menu
        self.json_menu.post(event.x_root, event.y_root)

    def _show_notes_context_menu(self, event) -> None:
        self.notes_text.focus_set()
        self._hide_context_menu()
        self.active_menu = self.notes_menu
        self.notes_menu.post(event.x_root, event.y_root)

    def _hide_field_menu_on_empty_space(self, event) -> None:
        if self.active_menu is not self.field_menu:
            return
        row_id = self.fields_tree.identify_row(event.y)
        if not row_id:
            self._hide_context_menu()

    def _hide_context_menu(self, _event=None) -> None:
        if self.active_menu is not None:
            try:
                self.active_menu.unpost()
            except tk.TclError:
                pass
            self.active_menu = None

    def _selected_field(self) -> FieldTableRow | None:
        selected = self.fields_tree.selection()
        if not selected:
            return None
        return self.field_rows_by_iid.get(selected[0])

    def _copy_to_clipboard(self, text: str, status: str) -> str:
        self.clipboard_clear()
        self.clipboard_append(text)
        self.status_var.set(status)
        self._hide_context_menu()
        return 'break'

    def _copy_selected_field_value(self) -> str | None:
        row = self._selected_field()
        if not row:
            return None
        return self._copy_to_clipboard(row.copy_value, 'Значение поля скопировано')

    def _copy_selected_field_name(self) -> str | None:
        row = self._selected_field()
        if not row:
            return None
        return self._copy_to_clipboard(row.field, 'Имя поля скопировано')

    def _copy_selected_field_row(self) -> str | None:
        row = self._selected_field()
        if not row:
            return None
        return self._copy_to_clipboard(f'{row.field}: {row.copy_value}', 'Строка скопирована')

    def _copy_selected_json_text(self, _event=None) -> str:
        if not self.reveal_var.get():
            # In hidden mode, all copy actions must return real secrets.
            return self._copy_json() or 'break'
        try:
            selected = self.json_text.get('sel.first', 'sel.last')
        except tk.TclError:
            return self._copy_json() or 'break'
        return self._copy_to_clipboard(selected, 'Выделенный JSON скопирован')

    def _copy_selected_notes_text(self, _event=None) -> str:
        try:
            selected = self.notes_text.get('sel.first', 'sel.last')
        except tk.TclError:
            selected = self.notes_text.get('1.0', 'end-1c')
        if not selected:
            return 'break'
        return self._copy_to_clipboard(selected, 'Фрагмент notesPlain скопирован')

    def _copy_json(self) -> str | None:
        uuid = self._selected_uuid()
        if not uuid:
            return None
        try:
            payload = self._get_payload(uuid)
            text = json.dumps(payload, ensure_ascii=False, indent=2)
            return self._copy_to_clipboard(text, 'JSON скопирован в буфер обмена')
        except Exception as exc:
            messagebox.showerror(APP_NAME, f'Не удалось скопировать JSON:\n{exc}')
            return None

    def _update_quick_copy_buttons(self) -> None:
        normalized = {normalize_alias(key): value for key, value in self.quick_fields.items() if value}
        for field_key, _label, aliases in QUICK_COPY_SPECS:
            enabled = any(normalize_alias(alias) in normalized for alias in aliases)
            self.quick_copy_buttons[field_key].configure(state='normal' if enabled else 'disabled')

    def _copy_quick_field(self, field_key: str) -> None:
        normalized = {normalize_alias(key): value for key, value in self.quick_fields.items() if value}
        spec = next((spec for spec in QUICK_COPY_SPECS if spec[0] == field_key), None)
        if spec is None:
            return
        _field_key, label, aliases = spec
        for alias in aliases:
            value = normalized.get(normalize_alias(alias))
            if value:
                self._copy_to_clipboard(value, f'{label} — готово')
                return

    def _configure_readonly_text(self, widget: tk.Text) -> None:
        for sequence in (
            '<Key>',
            '<<Cut>>',
            '<<Paste>>',
            '<<Clear>>',
            '<BackSpace>',
            '<Delete>',
            '<Control-v>',
            '<Control-x>',
        ):
            widget.bind(sequence, lambda _event: 'break')

    @staticmethod
    def _set_text(widget: tk.Text, text: str) -> None:
        widget.configure(state='normal')
        widget.delete('1.0', 'end')
        widget.insert('1.0', text)
        widget.configure(state='disabled')



def normalize_display_value(value: Any) -> str:
    if value is None:
        return ''
    if isinstance(value, bool):
        return 'true' if value else 'false'
    if isinstance(value, (int, float)):
        return str(value)
    return str(value).strip()


def build_search_blob(data: Any) -> str:
    tokens: list[str] = []

    def walk(obj: Any) -> None:
        if isinstance(obj, dict):
            for key, value in obj.items():
                key_text = str(key).strip()
                if key_text:
                    tokens.append(key_text)
                walk(value)
            return
        if isinstance(obj, list):
            for value in obj:
                walk(value)
            return
        text = normalize_display_value(obj)
        if text:
            tokens.append(text)

    walk(data)
    return ' '.join(tokens).casefold()



def friendly_label(path: str) -> str:
    path = path.replace('notesplain', 'notes')
    path = path.replace('typeName', 'type name')
    return path


def extract_notes_plain(data: Any) -> str:
    if not isinstance(data, dict):
        return ''
    value = data.get('notesPlain')
    if value is None:
        return ''
    return normalize_display_value(value)



def flatten_for_table(data: Any) -> list[FlatTableRow]:
    rows: list[FlatTableRow] = []

    def add_row(path: str, value: Any) -> None:
        label = friendly_label(path)
        text = normalize_display_value(value)
        if not label or not text:
            return
        path_key = path.casefold()
        if path_key in SKIP_PATHS or path_key == 'notesplain':
            return
        rows.append(FlatTableRow(path=path, field=label, value=text))

    def walk(path: str, obj: Any) -> None:
        if isinstance(obj, dict):
            for key, value in obj.items():
                next_path = f'{path}.{key}' if path else str(key)
                walk(next_path, value)
            return
        if isinstance(obj, list):
            simple_items = [normalize_display_value(v) for v in obj if not isinstance(v, (dict, list))]
            simple_items = [v for v in simple_items if v]
            if simple_items and len(simple_items) == len(obj):
                add_row(path, ', '.join(simple_items))
                return
            for index, value in enumerate(obj):
                walk(f'{path}[{index}]', value)
            return
        add_row(path, obj)

    walk('', data)

    def sort_key(item: FlatTableRow) -> tuple[int, str]:
        label = item.field.casefold()
        tail = label.split('.')[-1]
        return (PREFERRED_FIELD_ORDER.get(tail, 1000), label)

    deduped: list[FlatTableRow] = []
    seen: set[tuple[str, str]] = set()
    for row in sorted(rows, key=sort_key):
        key = (row.path, row.value)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(row)
    return deduped



def normalize_alias(name: str) -> str:
    return name.casefold().replace('_', ' ').strip()



def combine_field_rows(display_rows: list[FlatTableRow], copy_rows: list[FlatTableRow]) -> list[FieldTableRow]:
    copy_by_path = {row.path: row.value for row in copy_rows}
    result: list[FieldTableRow] = []
    for row in display_rows:
        result.append(
            FieldTableRow(
                field=row.field,
                display_value=row.value,
                copy_value=copy_by_path.get(row.path, row.value),
            )
        )
    return result



def pick_quick_fields(rows: list[FlatTableRow]) -> dict[str, str]:
    picked: dict[str, str] = {}
    for row in rows:
        if not row.value:
            continue
        tail = normalize_alias(row.field.split('.')[-1])
        if tail.startswith('fields['):
            continue
        picked.setdefault(tail, row.value)
    return picked



def load_config() -> dict[str, Any]:
    try:
        return json.loads(CONFIG_PATH.read_text(encoding='utf-8'))
    except Exception:
        return {}



def save_config(data: dict[str, Any]) -> None:
    APP_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')



def get_last_vault_path() -> str | None:
    config = load_config()
    value = config.get('last_vault_path')
    if isinstance(value, str) and value.strip():
        return value
    return None



def get_show_secrets_enabled() -> bool:
    config = load_config()
    value = config.get('show_secrets')
    if isinstance(value, bool):
        return value
    return False



def set_last_vault_path(path: Path) -> None:
    config = load_config()
    config['last_vault_path'] = str(path.expanduser().resolve())
    save_config(config)



def set_show_secrets_enabled(value: bool) -> None:
    config = load_config()
    config['show_secrets'] = bool(value)
    save_config(config)



def _make_hidden_root() -> tk.Tk:
    root = tk.Tk(className=APP_CLASS)
    root.withdraw()
    root.title(APP_NAME)
    try:
        root.iconname(APP_NAME)
    except tk.TclError:
        pass
    icon_path = resolve_icon_path()
    if icon_path is not None:
        try:
            root._icon_image = tk.PhotoImage(file=str(icon_path))
            root.iconphoto(True, root._icon_image)
        except tk.TclError:
            pass
    return root



def _choose_vault_path(initial_path: str | None) -> Path | None:
    candidate = initial_path or get_last_vault_path()
    if candidate:
        try:
            path = normalize_vault_path(candidate)
            if path.exists():
                return path
        except AgileViewError:
            pass

    root = _make_hidden_root()
    try:
        return _ask_vault_path(parent=root, initial_dir=None)
    finally:
        root.destroy()


def _ask_vault_path(parent: tk.Misc, initial_dir: str | None) -> Path | None:
    while True:
        chosen = filedialog.askdirectory(
            title=f'{APP_NAME} — выбери папку vault (.agilekeychain / .opvault / .cloudkeychain)',
            parent=parent,
            initialdir=initial_dir or str(Path.home()),
        )
        if not chosen:
            return None
        try:
            return normalize_vault_path(chosen)
        except AgileViewError as exc:
            messagebox.showerror(APP_NAME, str(exc), parent=parent)



def unlock_with_password_fallback(
    reader: VaultReader,
    cached_password: str,
    request_password: Callable[[], str | None],
) -> UnlockWithFallbackResult:
    try:
        reader.unlock(cached_password)
        return UnlockWithFallbackResult(success=True, password=cached_password)
    except Exception as first_exc:
        retry_password = request_password()
        if not retry_password:
            return UnlockWithFallbackResult(
                success=False,
                password=cached_password,
                first_error=first_exc,
                prompted=True,
                cancelled=True,
            )
        try:
            reader.unlock(retry_password)
            return UnlockWithFallbackResult(
                success=True,
                password=retry_password,
                first_error=first_exc,
                prompted=True,
            )
        except Exception as second_exc:
            return UnlockWithFallbackResult(
                success=False,
                password=cached_password,
                first_error=first_exc,
                second_error=second_exc,
                prompted=True,
                cancelled=False,
            )



def _ask_password(parent: tk.Misc | None = None) -> str | None:
    if parent is not None:
        return simpledialog.askstring(APP_NAME, 'Master password:', show='*', parent=parent)
    root = _make_hidden_root()
    try:
        return simpledialog.askstring(APP_NAME, 'Master password:', show='*', parent=root)
    finally:
        root.destroy()



def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='GUI viewer for legacy 1Password vaults')
    parser.add_argument('--path', help='Путь к 1Password vault (.agilekeychain/.opvault/.cloudkeychain)')
    return parser.parse_args()



def main() -> int:
    args = parse_args()

    try:
        path = _choose_vault_path(args.path)
        if path is None:
            return 130

        password = _ask_password()
        if not password:
            return 130

        reader = VaultReader(path)
        reader.unlock(password)
        set_last_vault_path(path)
        items = reader.list_items()

        app = AgileViewGUI(reader, items, master_password=password)
        app.mainloop()
        return 0
    except AgileViewError as exc:
        messagebox.showerror(APP_NAME, str(exc))
        return 2
    except Exception as exc:
        messagebox.showerror(APP_NAME, f'Неожиданная ошибка:\n{exc}')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
