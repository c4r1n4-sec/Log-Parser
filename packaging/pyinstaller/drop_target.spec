# PyInstaller one-folder spec for the portable drag/drop EXE.
# Build command (from repository root, after dependencies are installed):
#   pyinstaller --clean --noconfirm packaging/pyinstaller/drop_target.spec
#
# This spec creates a portable folder only. It does not create an installer,
# MSI, setup.exe, service, scheduled task, telemetry, auto-update, or cloud-call
# logic.

from pathlib import Path

block_cipher = None
project_root = Path.cwd()


a = Analysis(
    [str(project_root / "app" / "drop_target.py")],
    pathex=[str(project_root)],
    binaries=[],
    datas=[
        (str(project_root / "app" / "config" / "defaults.json"), "config"),
        (str(project_root / "rules"), "rules"),
        (str(project_root / "templates"), "templates"),
        (str(project_root / "tools"), "tools"),
        (str(project_root / "DROP-CUSTOMER-LOGS-HERE.bat"), "."),
        (str(project_root / "README-DROP-MODE.txt"), "."),
    ],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="TDSYNNEX-CB-LogParser",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    version=str(project_root / "packaging" / "pyinstaller" / "version_info.txt"),
)
coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="TDSYNNEX-CB-LogParser",
)
