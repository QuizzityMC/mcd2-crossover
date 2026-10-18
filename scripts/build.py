#!/usr/bin/env python3
"""Build only original compatibility code; no SDK/game binaries are bundled."""
import os,shutil,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'build';OUT.mkdir(exist_ok=True)
SRC=ROOT/'src'
link=shutil.which('lld-link')
if not link:
    candidates=sorted((Path.home()/'.rustup/toolchains').glob('*/lib/rustlib/*/bin/gcc-ld/lld-link'), key=lambda p:(not p.parts[-7].startswith('stable'),str(p)))
    if candidates:
        stable=[p for p in candidates if 'stable-' in str(p)]
        link=str((stable or candidates)[0])
if not link:raise SystemExit('Install LLVM (lld-link) or Rust, then run this build again.')
clang=shutil.which('clang')
def run(args):subprocess.run(list(map(str,args)),check=True)
def obj(source,name):
    run([clang,'--target=x86_64-pc-windows-msvc','-O1','-fno-stack-protector','-fno-builtin','-c',SRC/source,'-o',OUT/name])
def lib(name):run([link,'/lib','/machine:x64','/def:'+str(SRC/(name+'-kernel32.def')),'/out:'+str(OUT/(name+'-kernel32.lib'))])
for n in ('runtime','curl','ui'):lib(n)
obj('forward.s','forward.obj')
obj('stack-probe.s','stack-probe.obj')
for n in ('user32','gdi32'):run([link,'/lib','/machine:x64','/def:'+str(SRC/('ui-'+n+'.def')),'/out:'+str(OUT/('ui-'+n+'.lib'))])
obj('runtime.c','runtime.obj')
run([link,'/dll','/entry:DllMain','/nodefaultlib','/def:'+str(SRC/'runtime.def'),'/out:'+str(OUT/'xgameruntime.dll'),OUT/'runtime.obj',OUT/'forward.obj',OUT/'runtime-kernel32.lib',OUT/'stack-probe.obj'])
obj('curl.c','curl.obj')
run([link,'/dll','/entry:DllMain','/nodefaultlib','/def:'+str(SRC/'curl.def'),'/out:'+str(OUT/'XCurl.dll'),OUT/'curl.obj',OUT/'curl-kernel32.lib',OUT/'stack-probe.obj'])
obj('signin-ui.c','signin-ui.obj')
run([link,'/subsystem:windows','/entry:mainCRTStartup','/nodefaultlib','/out:'+str(OUT/'signin-ui.exe'),OUT/'signin-ui.obj',OUT/'ui-kernel32.lib',OUT/'ui-user32.lib',OUT/'ui-gdi32.lib',OUT/'stack-probe.obj'])
# Small Windows observers: no SDK or proprietary binaries are required.
for n in ('kernel32','ntdll','dbghelp'):
    run([link,'/lib','/machine:x64','/def:'+str(SRC/('freeze-'+n+'.def')),'/out:'+str(OUT/('freeze-'+n+'.lib'))])
for source,name,flags in [('find_target.c','find-target',[]),('freeze_probe.c','identity-baseline',[]),('freeze_probe.c','identity-context',['-DCAPTURE_CONTEXT'])]:
    run([clang,'--target=x86_64-pc-windows-msvc','-O1','-fno-stack-protector','-fno-builtin',*flags,'-c',SRC/source,'-o',OUT/(name+'.obj')])
    run([link,'/entry:mainCRTStartup','/subsystem:console','/nodefaultlib','/out:'+str(OUT/(name+'.exe')),OUT/(name+'.obj'),OUT/'freeze-kernel32.lib',OUT/'freeze-ntdll.lib',OUT/'freeze-dbghelp.lib'])
run([clang,'-O2','-framework','Foundation','-framework','Security','-framework','LocalAuthentication',ROOT/'helper/keychain.m','-o',OUT/'keychain'])
run(['/usr/bin/codesign','--force','--sign','-',OUT/'keychain'])
run([clang,'-arch','arm64','-mmacosx-version-min=13.0','-fobjc-arc','-O2','-framework','Cocoa',ROOT/'helper/launcher.m','-o',OUT/'launcher'])
print('Built compatibility DLLs, sign-in UI, Keychain helper and Mac launcher.')
