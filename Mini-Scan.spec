# -*- mode: python ; coding: utf-8 -*-

# 注意：config 和 tools 文件夹不打包进 exe，作为外部文件夹存在
# 这样打包后仍然可以修改配置文件和更新 tools 中的工具版本

a = Analysis(
    ['main.py'],          # ← 入口改为 main.py
    pathex=[],
    binaries=[],
    datas=[],             # config 和 tools 文件夹不打包，作为外部文件夹
    hiddenimports=[
        'miniscan',
        'miniscan.config',
        'miniscan.cli',
        'miniscan.scanner',
        'miniscan.scanner.file_processor',
        'miniscan.scanner.fortify',
        'miniscan.wechat',
        'miniscan.wechat.hook',
        'miniscan.wechat.tools',
    ],
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
    name='Mini-Scan',     # exe 文件名保持不变
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
