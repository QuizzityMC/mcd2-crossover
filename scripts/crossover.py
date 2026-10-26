"""Resolve the user's CrossOver or Whisky installation without starting it."""
import json
import os
import plistlib
from pathlib import Path

WINE_RELATIVE = 'Contents/SharedSupport/CrossOver/bin/wine'
WHISKY_CMD_RELATIVE = 'Contents/Resources/WhiskyCmd'
RUNTIMES = {
    'com.codeweavers.CrossOver': (WINE_RELATIVE,),
    'com.franke.Whisky': (WINE_RELATIVE, WHISKY_CMD_RELATIVE),
    'com.isaacmarovitz.Whisky': (WINE_RELATIVE, WHISKY_CMD_RELATIVE),
}


def _resolve_runtime(app, identifier):
    for relative in RUNTIMES.get(identifier, ()):
        executable = app / relative
        if executable.is_file() and os.access(executable, os.X_OK):
            return executable
    return None


def validate_app(path):
    app = Path(path).expanduser().resolve()
    try:
        with (app / 'Contents/Info.plist').open('rb') as stream:
            info = plistlib.load(stream)
            identifier = info.get('CFBundleIdentifier') if isinstance(info, dict) else None
        if identifier not in RUNTIMES:
            raise ValueError('The selected app is not CrossOver or Whisky.')
        runtime = _resolve_runtime(app, identifier)
        if runtime is None:
            raise ValueError('The selected app is missing its runtime executable.')
    except (OSError, plistlib.InvalidFileException) as error:
        raise ValueError(f'Cannot read the selected app: {app}. Choose it again.') from error
    return app


def _wine_executable(app):
    with (app / 'Contents/Info.plist').open('rb') as stream:
        info = plistlib.load(stream)
    identifier = info.get('CFBundleIdentifier') if isinstance(info, dict) else None
    runtime = _resolve_runtime(app, identifier)
    if runtime is None:
        raise ValueError('The selected app is missing its runtime executable.')
    return runtime


def crossover_app():
    preference = Path.home() / 'Library/Application Support/DungeonsCrossOver/crossover-app.json'
    selected = os.environ.get('MCD2_CROSSOVER_APP')
    if not selected and preference.exists():
        try:
            selected = json.loads(preference.read_text())['path']
            if not isinstance(selected, str) or not selected:
                raise ValueError('empty path')
        except (OSError, ValueError, KeyError, TypeError) as error:
            raise ValueError('Cannot read the saved CrossOver selection. Choose CrossOver again.') from error
    if selected:
        # Never silently launch a different installation if a saved one moved.
        return validate_app(selected)
    for directory in (Path('/Applications'), Path.home() / 'Applications'):
        candidates = [directory / 'CrossOver.app', directory / 'Whisky.app', *sorted(directory.glob('*.app'))]
        for candidate in candidates:
            try:
                return validate_app(candidate)
            except ValueError:
                continue
    raise ValueError('CrossOver was not found. Click Choose CrossOver and select your CrossOver app.')


def wine():
    return str(_wine_executable(crossover_app()))
