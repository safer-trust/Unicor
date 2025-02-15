# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['unicor.py'],
    pathex=[],
    binaries=[('/usr/local/lib/python3.10/dist-packages/pymisp', 'pymisp')],
    datas=[('subcommands/','subcommands/'), ('utils/', 'utils/')],
    hiddenimports=['pymisp','asyncio','cachetools','pytz','jsonlines','smtplib','jinja2','email.mime','email.mime.text','email.mime.multipart'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='unicor',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
