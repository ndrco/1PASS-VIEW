from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

APP_NAME = '1Pass-view'
APP_CLASS = '1PassView'
BASE_DIR = Path(__file__).resolve().parent
ICON_PATH = BASE_DIR / 'assets' / '1pass-view.png'
DESKTOP_PATH = Path.home() / '.local' / 'share' / 'applications' / '1pass-view.desktop'


def main() -> int:
    DESKTOP_PATH.parent.mkdir(parents=True, exist_ok=True)

    exec_path = f'{sys.executable} "{BASE_DIR / "agileview_gui.py"}"'
    icon_path = ICON_PATH if ICON_PATH.exists() else BASE_DIR / 'assets' / '1pass-view-256.png'

    desktop = f"""[Desktop Entry]
Version=1.0
Type=Application
Name={APP_NAME}
Comment=Read-only viewer for legacy 1Password.agilekeychain vaults
Exec={exec_path}
Icon={icon_path}
Terminal=false
Categories=Utility;Security;
StartupWMClass={APP_CLASS}
Keywords=1Password;Agile Keychain;Vault;Passwords;
"""

    DESKTOP_PATH.write_text(desktop, encoding='utf-8')
    current_mode = DESKTOP_PATH.stat().st_mode
    DESKTOP_PATH.chmod(current_mode | stat.S_IXUSR)

    print(f'Desktop entry installed: {DESKTOP_PATH}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
