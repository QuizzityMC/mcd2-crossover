"""Bounded on-demand diagnostic runner. Launches only an explicitly supplied diagnostic command.

No game selection, restart, debugger attachment, or process-group termination.
Context collection can briefly interrupt target threads under Wine. The observer never attaches a debugger or explicitly suspends/resumes the game.
"""
import json
import os
import selectors
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path


def _capture(command, timeout=10, limit=2 * 1024 * 1024, env=None):
    started = time.monotonic()
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    selector = selectors.DefaultSelector()
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    events = []
    ignored_lines = 0
    reason = None
    for name in buffers:
        stream = getattr(proc, name)
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ, name)
    total = 0
    try:
        while selector.get_map():
            remaining = timeout - (time.monotonic() - started)
            if remaining <= 0:
                reason = "deadline"
                break
            for key, _ in selector.select(min(remaining, 0.1)):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                total += len(chunk)
                if total > limit:
                    reason = "output_limit"
                    break
                buf = buffers[key.data]
                buf.extend(chunk)
                if key.data == "stderr":
                    while b"\n" in buf:
                        line, _, rest = buf.partition(b"\n")
                        buf[:] = rest
                        try:
                            item = json.loads(line)
                            if (not isinstance(item, dict) or set(item) != {"phase", "tid"}
                                    or item["phase"] not in {
                                        "started", "open_process", "modules", "symbols",
                                        "debugger_state", "thread_list", "thread_metadata",
                                        "thread_context", "thread_stack", "thread_complete", "complete"}
                                    or type(item["tid"]) is not int):
                                raise ValueError("not a diagnostic phase")
                            events.append({**item, "elapsed_ms": round((time.monotonic()-started)*1000)})
                        except (ValueError, TypeError):
                            ignored_lines += 1
            if reason:
                break
        if reason:
            # Popen owns this child; never signal the game, wineserver or a group.
            if proc.poll() is None:
                proc.kill()
            proc.wait(timeout=2)
        else:
            remaining = max(0.01, timeout - (time.monotonic() - started))
            try:
                proc.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                reason = "deadline_after_output_closed"
                proc.kill()
                proc.wait(timeout=2)
    finally:
        selector.close()
        for name in buffers:
            getattr(proc, name).close()
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=2)
    report = None
    try:
        report = json.loads(buffers["stdout"])
    except (ValueError, UnicodeDecodeError):
        # Recover complete thread objects if a later context call blocks.
        try:
            raw = buffers["stdout"].decode("utf-8")
            prefix, tail = raw.split('"threads":[', 1)
            report = json.loads(prefix + '"threads":[]}')
            decoder = json.JSONDecoder()
            while tail:
                tail = tail.lstrip(' ,\r\n')
                try: item, end = decoder.raw_decode(tail)
                except ValueError: break
                if not isinstance(item, dict): break
                report["threads"].append(item)
                tail = tail[end:]
            report["partial"] = True
        except (ValueError, UnicodeDecodeError):
            report = None
    return {"exit_code": proc.returncode, "stop_reason": reason,
            "elapsed_ms": round((time.monotonic()-started)*1000),
            "phases": events, "last_phase": events[-1] if events else None,
            "ignored_stderr_lines": ignored_lines, "report": report,
            "report_complete": isinstance(report, dict) and not report.get("partial") and proc.returncode == 0 and reason is None}


def capture(command, timeout=10, limit=2 * 1024 * 1024, observer_image=None, env=None):
    if observer_image is None:
        return _capture(command, timeout, limit, env)
    image = Path(observer_image).resolve(strict=True)
    if command.count(str(image)) != 1 or image.suffix.lower() != ".exe":
        raise ValueError("command must contain the exact diagnostic observer image once")
    with tempfile.TemporaryDirectory(prefix="mcd2-observer-") as folder:
        private_image = Path(folder).resolve() / "observer.exe"
        shutil.copyfile(image, private_image)
        private_command = [str(private_image) if arg == str(image) else arg for arg in command]
        expected = {str(private_image), "Z:" + str(private_image).replace("/", "\\")}

        def owned_processes():
            listing = subprocess.run(["/bin/ps", "-axo", "pid=,comm="],
                                     capture_output=True, text=True, timeout=2, check=True)
            found = []
            for line in listing.stdout.splitlines():
                parts = line.strip().split(None, 1)
                if len(parts) == 2 and parts[1] in expected:
                    found.append(int(parts[0]))
            return found

        result = None
        killed = []
        cleanup_error = False
        try:
            result = _capture(private_command, timeout, limit, env)
        finally:
            try:
                # Wine can detach from the launcher. Match only this invocation's
                # freshly created image, never a generic Wine/game process name.
                for _ in range(3):
                    matches = owned_processes()
                    if not matches:
                        time.sleep(0.05)
                        continue
                    for pid in matches:
                        if pid in owned_processes():
                            try:
                                os.kill(pid, signal.SIGKILL)
                                killed.append(pid)
                            except ProcessLookupError:
                                pass
                    time.sleep(0.05)
                remaining = owned_processes()
            except (OSError, subprocess.SubprocessError):
                cleanup_error = True
                remaining = None
            if result is not None:
                result["observer_cleanup"] = {"killed_count": len(set(killed)),
                                              "remaining_count": None if remaining is None else len(remaining),
                                              "error": cleanup_error}
                if cleanup_error or remaining:
                    result["report_complete"] = False
                    result["stop_reason"] = result["stop_reason"] or "observer_cleanup_failed"
        return result


def capture_pair(baseline_command, context_command, timeout=10, observer_images=None, env=None):
    images = observer_images or (None, None)
    baseline = capture(baseline_command, timeout, observer_image=images[0], env=env)
    # A failed baseline is evidence of a prior failure; do not add context work.
    context = capture(context_command, timeout, observer_image=images[1], env=env) if baseline["report_complete"] else None
    return {"baseline": baseline, "context": context}
