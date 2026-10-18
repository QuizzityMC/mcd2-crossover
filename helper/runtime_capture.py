"""Windows-side freeze evidence; no credentials, paths or command lines exported."""
import json
import subprocess
import time
from pathlib import Path

STATES = {'selecting','selection_failed','selection_invalid','capturing_baseline',
          'baseline_failed','capturing_context','captured','context_incomplete',
          'observer_unavailable','runtime_unavailable','capture_failed'}
NUMBERS = {'timestamp_ms','schema','windows_pid','creation_time','matched_count','unreadable_processes',
           'host_pid','pid','parent_pid','threads','tid','elapsed_ms','exit_code','ignored_stderr_lines',
           'killed_count','remaining_count','code','identity_verified','debug_query_ok',
           'debugger_present','debug_query_error','thread_list_error','symbols_ok','suspend_status','suspend_count','start_status',
           'start_address','start_rva','open_error','context_error','context_ok','rip','rsp','pc'}
BOOLS = {'report_complete','partial','error'}
MODULES = {'[other-module]','ntdll.dll','kernel32.dll','kernelbase.dll',
           'Dungeons-Win64-Shipping.exe','Dungeons-WinGDK-Shipping.exe','steamclient64.dll',
           'GameOverlayRenderer64.dll','libcef.dll','chrome_elf.dll','dbghelp.dll',
           'xgameruntime.dll','xgameruntime-native.dll','XCurl.dll'}
ROLES = {'[other-process]','Dungeons-Win64-Shipping.exe','Dungeons-WinGDK-Shipping.exe',
         'CrashReportClient.exe','winedbg.exe','WerFault.exe','steam.exe','steamwebhelper.exe',
         'UnrealCEFSubProcess.exe','crashpad_handler.exe','wine','wine64','wine64-preloader','wine-preloader','wineserver','winedbg'}
PHASES = {'started','open_process','modules','symbols','debugger_state','thread_list',
          'thread_metadata','thread_context','thread_stack','thread_complete','complete'}
ERRORS = {'expected_image_unreadable','process_list_failed','process_list_empty_or_failed',
          'process_list_incomplete','pid_required','open_process','target_identity_changed'}
REASONS = {'deadline','output_limit','deadline_after_output_closed','observer_cleanup_failed'}
OBJECTS = {'selection','baseline','context','report','last_phase','observer_cleanup'}
ARRAYS = {'host_processes':512,'processes':512,'threads':4096,'windows_stack':32,'phases':24000}


def safe_report(doc):
    if not isinstance(doc,dict) or doc.get('status') not in STATES:
        return None
    def clean(value, depth=0):
        if not isinstance(value,dict) or depth>8: return {}
        out={}
        for k,v in value.items():
            if k in NUMBERS and type(v) is int and -255<=v<=2**64-1: out[k]=v
            elif k in BOOLS and type(v) is bool: out[k]=v
            elif k=='status' and isinstance(v,str) and v in STATES: out[k]=v
            elif k=='error' and isinstance(v,str) and v in ERRORS: out[k]=v
            elif k=='stop_reason' and (v is None or isinstance(v,str) and v in REASONS): out[k]=v
            elif k=='phase' and isinstance(v,str) and v in PHASES: out[k]=v
            elif k=='start_module' and isinstance(v,str) and v in MODULES: out[k]=v
            elif k=='role' and isinstance(v,str) and v in ROLES: out[k]=v
            elif k in OBJECTS and isinstance(v,dict): out[k]=clean(v,depth+1)
            elif k in ARRAYS and isinstance(v,list): out[k]=[clean(x,depth+1) for x in v[:ARRAYS[k]] if isinstance(x,dict)]
        return out
    return clean(doc)


def host_processes():
    # Host runtime candidates are explicitly not attributed to the selected bottle.
    try:
        proc=subprocess.run(['/bin/ps','-axo','pid=,ppid=,comm='],capture_output=True,text=True,timeout=3,check=True)
        rows=[]
        for line in proc.stdout.splitlines():
            fields=line.strip().split(None,2)
            if len(fields)!=3:continue
            role=fields[2].replace('\\','/').rsplit('/',1)[-1]
            if role in ROLES and role!='[other-process]' and fields[0].isdigit() and fields[1].isdigit():
                rows.append({'host_pid':int(fields[0]),'parent_pid':int(fields[1]),'role':role})
        return rows[:512]
    except (OSError,subprocess.SubprocessError):return []


def capture(home, executable, bottle):
    from capture_selected import capture_selected, checkpoint
    from crossover import wine
    home=Path(home)
    output=home/'freeze-runtime.json'
    stamp=time.time_ns()//1000000
    result={'schema':1,'status':'capture_failed','timestamp_ms':stamp,'host_processes':host_processes()}
    checkpoint(output,result)
    try:
        here=Path(__file__).resolve().parent
        probes=here if (here/'find-target.exe').is_file() else here.parent/'build'
        if not all((probes/n).is_file() for n in ('find-target.exe','identity-baseline.exe','identity-context.exe')):
            result['status']='observer_unavailable'
        else:
            try: runtime=wine()
            except (ValueError,OSError): result['status']='runtime_unavailable'
            else:
                # Z: is Wine's host mapping. File identity, not spelling, selects the target.
                expected='Z:'+str(Path(executable).resolve()).replace('/','\\')
                result=capture_selected([runtime,'--bottle',str(Path(bottle).resolve()),'--debugmsg','-all'],
                                        probes,expected,output,timeout=10,initial={'timestamp_ms':stamp,'host_processes':result['host_processes']})
    except (OSError,ValueError,RuntimeError,subprocess.SubprocessError):
        # Keep a completed baseline when a later launch fails.
        try: result=safe_report(json.loads(output.read_text())) or result
        except (OSError,ValueError): pass
        result['status']='capture_failed'
    result['timestamp_ms']=stamp
    result=safe_report(result)
    checkpoint(output,result)
    return result


def saved_report(home):
    path=Path(home)/'freeze-runtime.json'
    try:
        if path.is_symlink() or path.stat().st_size>4*1024*1024:return None
        return safe_report(json.loads(path.read_text()))
    except (OSError,ValueError):return None
