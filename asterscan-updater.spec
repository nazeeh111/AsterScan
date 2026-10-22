# -*- mode: python -*-

a = Analysis(['asterscan-updater.py'],
             pathex=['.'],
             hiddenimports=[],
             hookspath=None,
             runtime_hooks=None)
pyz = PYZ(a.pure)

a.datas = list({tuple(map(str.upper, t)) for t in a.datas})

exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name='asterscan-updater.exe',
          debug=False,
          strip=None,
          upx=False,
          console=True , icon='asterscan.ico')
