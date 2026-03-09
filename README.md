# 1Pass-view

Read-only viewer for legacy `1Password.agilekeychain` and `1Password.opvault` vaults on Linux.

## GUI

```bash
python agileview_gui.py --path ~/Dropbox/Apps/1Password/1Password.legacyagilekeychain
```

Also supported:

```bash
python agileview_gui.py --path ~/Dropbox/Apps/1Password/1Password.opvault
```

If `--path` is omitted, the app reopens the last vault path from `~/.config/agileview/config.json`.
In the GUI, you can switch the current vault at runtime using the `Сменить vault...` button (or `Ctrl+O`).

### Copy and reload behavior

- With `Показать секретные поля` disabled, secrets stay masked in the UI.
- The `Показать секретные поля` checkbox state is persisted between launches.
- Search supports partial matches across title, UUID, category, field names, and field values.
- All copy actions (`quick-copy`, field context menu, JSON copy) use real decrypted values.
- In hidden mode, `Копировать выделенное` in the JSON tab copies full raw JSON.
- `Обновить` performs a real vault re-open (`unlock`) with cached password first; if it fails, the app asks for password once and keeps the current view on failure.

### Custom category rules

Additional explicit grouping rules are applied from decrypted payload markers:

- `sections[1].title = Покупатель` -> `Лицензии`
- `sections[1].title = SMTP` -> `Учетные записи почты`
- `cardholder = Контактная информация` -> `Кредитные карты`
- `sections[1].title = Консоль администрирования` -> `Серверы`
- `sections[0].fields[1].a.generate = off` -> `Номера социального страхования`
- `sections[0].fields[4].n = network_name` -> `Беспроводные маршрутизаторы`
- non-empty `fullname` -> `Водительские права`
- non-empty `notesPlain` -> `Защищенные заметки`

## Dependencies

```bash
sudo apt install python3-tk
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Run tests:

```bash
python -m unittest discover -s tests -p 'test_*.py'
```

## Contributing

See `CONTRIBUTING.md`.

## App icon and launcher

The project includes app icons in `assets/` and the GUI sets the window title to `1Pass-view`, loads the PNG icon with Tk, and uses `WM_CLASS=1PassView` for better taskbar integration.

For the best result in Linux application menus and taskbars, install the desktop entry:

```bash
python install_desktop_entry.py
```

This creates:

- `~/.local/share/applications/1pass-view.desktop`

with the correct app name, icon path, and `StartupWMClass`.

## License

MIT. See `LICENSE`.
