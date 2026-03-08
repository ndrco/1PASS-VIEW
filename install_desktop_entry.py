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


def resolve_python_executable() -> Path:
    # Prefer project-local virtualenv so desktop launch uses installed app dependencies.
    venv_python = BASE_DIR / '.venv' / 'bin' / 'python'
    if venv_python.exists() and os.access(venv_python, os.X_OK):
        return venv_python
    return Path(sys.executable)


def main() -> int:
    DESKTOP_PATH.parent.mkdir(parents=True, exist_ok=True)

    python_executable = resolve_python_executable()
    exec_path = f'{python_executable} "{BASE_DIR / "agileview_gui.py"}"'
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
    print(f'Using Python executable: {python_executable}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
