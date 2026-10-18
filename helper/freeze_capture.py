"""On-demand, bounded samples of the verified selected game; no network or signals.

Raw macOS sample metadata stays in a private temporary directory. Only call-graph
frames, numeric resource values and fixed outcomes survive into the support ZIP.
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

MAX_SAMPLE = 8 * 1024 * 1024
MAX_FRAMES = 12000
OUTCOMES = {'captured', 'game_not_running', 'ambiguous_game', 'settings_missing',
            'sample_denied', 'sample_timeout', 'sample_empty', 'process_changed', 'capture_failed'}
# Symbols are retained only from known system/Wine/graphics modules. Game and
# unrecognized modules retain addresses for comparison, without arbitrary names.
MODULE = re.compile(r'(?:lib(?:system_[a-z_]+|dispatch|dyld|pthread|objc|c\+\+|RosettaRuntime|unwind|metalirconverter)\.dylib|Metal|MetalKit|IOGPU|IOKit|CoreFoundation|Foundation|AppKit|QuartzCore|AGXMetal[A-Za-z0-9_]*|D3DMetal|d3dmetal(?:\.dll)?|wine(?:64)?(?:-preloader)?|(?:ntdll|kernelbase|kernel32|win32u|winevulkan|vulkan-1|d3d11|d3d12|dxgi|xgameruntime|xgameruntime-native|XCurl|curl-compat)\.(?:dll|so))')


def sample_frames(text):
    """Reconstruct frames, dropping process paths, thread names and image tables."""
    frames = []
    inside = False
    thread = 0
    for line in text.splitlines():
        if line.strip() == 'Call graph:':
            inside = True
            continue
        if not inside:
            continue
        if line.startswith(('Total number', 'Sort by', 'Binary Images:', 'External Modification')):
            break
        if 'Thread_' in line or re.search(r'\bThread\s+\d+', line):
            thread += 1
            continue
        match = re.match(r'^([ +|!:]*)(\d+)\s+(.+?)\s+\(in (.+?)\)(.*)$', line)
        if not match or len(frames) >= MAX_FRAMES:
            continue
        indent, count, symbol, module, tail = match.groups()
        # Raw names are never copied for unknown modules.
        known = bool(MODULE.fullmatch(module))
        safe_symbol = symbol if known and re.fullmatch(r'[A-Za-z_?$][A-Za-z0-9_:$?<>~.* +\[\](),-]{0,180}', symbol) else '[unresolved]'
        addresses = re.findall(r'\b0x[0-9a-fA-F]{1,16}\b', tail)
        frames.append({'thread': thread, 'depth': min(len(indent), 500),
                       'samples': min(int(count), 1000000), 'module': module if known else '[game-or-other-module]',
                       'symbol': safe_symbol, 'address': addresses[-1] if addresses else 'unknown'})
    return frames


def safe_report(doc):
    if not isinstance(doc, dict) or doc.get('outcome') not in OUTCOMES:
        return None
    result = {'outcome': doc['outcome']}
    for key, limit in [('timestamp_ms', 9999999999999), ('elapsed_ms', 180000),
                       ('rss_kib', 2**40), ('cpu_tenths', 1000000)]:
        if type(doc.get(key)) is int and 0 <= doc[key] <= limit:
            result[key] = doc[key]
    frames = []
    source_frames = doc.get('frames', [])
    if not isinstance(source_frames, list): source_frames = []
    for frame in source_frames[:MAX_FRAMES]:
        if not isinstance(frame, dict): continue
        if not all(type(frame.get(k)) is int and 0 <= frame[k] <= 1000000 for k in ('thread','depth','samples')): continue
        module = frame.get('module', '')
        symbol = frame.get('symbol', '')
        if not isinstance(module,str) or not isinstance(symbol,str): continue
        if not (module == '[game-or-other-module]' or MODULE.fullmatch(module)): continue
        if symbol != '[unresolved]' and (module == '[game-or-other-module]' or not re.fullmatch(r'[A-Za-z_?$][A-Za-z0-9_:$?<>~.* +\[\](),-]{0,180}',symbol)): continue
        address = frame.get('address', '')
        if not isinstance(address,str): continue
        if address != 'unknown' and not re.fullmatch(r'0x[0-9a-fA-F]{1,16}',address): continue
        frames.append({k:frame[k] for k in ('thread','depth','samples','module','symbol','address')})
    result['frames'] = frames
    return result


def capture(home, *, inspect=None, run=None):
    import diagnostics as d
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'scripts'))
    from game_process import inspect_processes
    inspect = inspect or (lambda executable,bottle: inspect_processes(executable,bottle,budget_seconds=5))
    run = run or subprocess.run
    home = d._private_home(home)
    stamp, start = time.time_ns() // 1000000, time.monotonic_ns()
    report = {'timestamp_ms': stamp, 'outcome': 'capture_failed', 'frames': []}
    def finish(outcome):
        report['outcome'] = outcome
        report['elapsed_ms'] = (time.monotonic_ns()-start)//1000000
        # Validate again on export; never export a raw sample.
        d._write_json(home/'freeze.json', safe_report(report))
        d.record(home, 'freeze_capture', {'outcome': 'success' if outcome=='captured' else 'failed'})
        return {'ok': outcome=='captured', 'capture_outcome': outcome, 'available': True,
                'active': d.enabled(home), 'frames': len(report['frames'])}
    settings = d._read_json(home/'settings.json')
    if not isinstance(settings,dict) or not isinstance(settings.get('bottle'),str) or not isinstance(settings.get('game'),str):
        return finish('settings_missing')
    try:
        bottle_name, game = settings['bottle'], Path(settings['game'])
        if not isinstance(bottle_name,str) or not bottle_name or bottle_name in {'.','..'} or '/' in bottle_name or '\\' in bottle_name or not game.is_absolute():
            return finish('settings_missing')
        binary = Path(settings.get('binary',game/'Dungeons/Binaries/Win64'))
        if binary.resolve() not in {(game/'Dungeons/Binaries/Win64').resolve(), (game/'Dungeons/Binaries/WinGDK').resolve()}:
            return finish('settings_missing')
        executable = binary / ('Dungeons-WinGDK-Shipping.exe' if binary.name=='WinGDK' else 'Dungeons-Win64-Shipping.exe')
        if not executable.is_file(): return finish('settings_missing')
        bottle = Path.home()/'Library/Application Support/CrossOver/Bottles'/bottle_name
        identity = inspect(executable,bottle)
        if identity.ambiguous or len(identity.selected_pids)>1: return finish('ambiguous_game')
        if not identity.selected_pids: return finish('game_not_running')
        pid = identity.selected_pids[0]
        # Capture process creation time to reject PID reuse across the sample.
        def birth():
            p=run(['/bin/ps','-p',str(pid),'-o','lstart='],capture_output=True,text=True,timeout=3,check=False)
            return p.stdout.strip() if p.returncode==0 else ''
        before = birth()
        if not before: return finish('process_changed')
        p=run(['/bin/ps','-p',str(pid),'-o','%cpu=,rss='],capture_output=True,text=True,timeout=3,check=False)
        values=p.stdout.split()
        if p.returncode==0 and len(values)==2:
            try: report.update(cpu_tenths=int(float(values[0])*10),rss_kib=int(values[1]))
            except (ValueError,OverflowError): pass
        with tempfile.TemporaryDirectory(prefix='.freeze-',dir=home) as temp:
            target=Path(temp)/'sample.txt'
            try:
                sampled=run(['/usr/bin/sample',str(pid),'3','10','-file',str(target)],
                            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15,check=False)
            except subprocess.TimeoutExpired: return finish('sample_timeout')
            if sampled.returncode: return finish('sample_denied')
            after=inspect(executable,bottle)
            if after.ambiguous or after.selected_pids!=(pid,) or birth()!=before: return finish('process_changed')
            if not d._regular(target) or target.stat().st_size>MAX_SAMPLE: return finish('sample_empty')
            report['frames']=sample_frames(target.read_text(errors='replace'))
        return finish('captured' if report['frames'] else 'sample_empty')
    except (KeyError,TypeError,ValueError,OSError,RuntimeError,subprocess.SubprocessError):
        return finish('capture_failed')
