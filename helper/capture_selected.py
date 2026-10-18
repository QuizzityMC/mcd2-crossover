"""On-demand orchestration for one selected executable in one Wine bottle.

The caller supplies the Wine command configured for the already-running bottle.
This does not launch the game. The context pass can transiently interrupt threads.
Output checkpoints keep completed phases if a later operation fails.
"""
import json
import os
from pathlib import Path
import tempfile
from bounded_capture import capture


def checkpoint(path, report):
    path = Path(path)
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, prefix=".capture-", delete=False) as f:
        temporary = Path(f.name)
        try:
            json.dump(report, f, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def capture_selected(wine_command, probe_directory, expected_image, output, timeout=10, initial=None):
    probes = Path(probe_directory).resolve()
    env = dict(os.environ, MCD2_CAPTURE_EXPECTED_IMAGE=expected_image)
    env.pop("MCD2_CAPTURE_EXPECTED_CREATED", None)
    result = {"schema": 1, "status": "selecting", "selection": None,
              "baseline": None, "context": None}
    result.update(initial or {})
    checkpoint(output, result)
    finder = probes / "find-target.exe"
    result["selection"] = capture(wine_command+[str(finder)], timeout=timeout,
                                  observer_image=finder, env=env)
    selected = result["selection"]
    if not selected["report_complete"]:
        result["status"] = "selection_failed"
        checkpoint(output, result)
        return result
    identity = selected["report"]
    if (identity.get("matched_count") != 1 or type(identity.get("windows_pid")) is not int
            or type(identity.get("creation_time")) is not int):
        result["status"] = "selection_invalid"
        checkpoint(output, result)
        return result
    env["MCD2_CAPTURE_EXPECTED_CREATED"] = str(identity["creation_time"])
    pid = str(identity["windows_pid"])
    result["status"] = "capturing_baseline"
    checkpoint(output, result)
    baseline = probes / "identity-baseline.exe"
    result["baseline"] = capture(wine_command+[str(baseline),pid], timeout=timeout,
                                 observer_image=baseline, env=env)
    metadata=result["baseline"].get("report") or {}
    if not metadata.get("threads") or metadata.get("thread_list_error"):
        result["baseline"]["report_complete"]=False
    if not result["baseline"]["report_complete"]:
        result["status"] = "baseline_failed"
        checkpoint(output, result)
        return result
    # Persist the baseline before any potentially blocking context request.
    result["status"] = "capturing_context"
    checkpoint(output, result)
    context = probes / "identity-context.exe"
    result["context"] = capture(wine_command+[str(context),pid], timeout=timeout,
                                observer_image=context, env=env)
    contexts=result["context"].get("report") or {}
    if (contexts.get("thread_list_error") or not contexts.get("threads")
            or any(not t.get("context_ok") or not t.get("windows_stack") for t in contexts.get("threads",[]))):
        result["context"]["report_complete"]=False
    result["status"] = "captured" if result["context"]["report_complete"] else "context_incomplete"
    checkpoint(output, result)
    return result
