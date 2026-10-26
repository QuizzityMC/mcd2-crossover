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
BOTTLE_ROOTS = {
    'com.codeweavers.CrossOver': ('Library', 'Application Support', 'CrossOver', 'Bottles'),
    'com.franke.Whisky': ('Library', 'Containers', 'com.franke.Whisky', 'Bottles'),
    'com.isaacmarovitz.Whisky': ('Library', 'Containers', 'com.isaacmarovitz.Whisky', 'Bottles'),
}


def _resolve_runtime(app, identifier):
    for relative in RUNTIMES.get(identifier, ()):
        executable = app / relative
        if executable.is_file() and os.access(executable, os.X_OK):
            return executable
    return None


def _identifier(app):
    with (app / 'Contents/Info.plist').open('rb') as stream:
        info = plistlib.load(stream)
    return info.get('CFBundleIdentifier') if isinstance(info, dict) else None


def validate_app(path):
    app = Path(path).expanduser().resolve()
    try:
        identifier = _identifier(app)
        if identifier not in RUNTIMES:
            raise ValueError('The selected app is not CrossOver or Whisky.')
        runtime = _resolve_runtime(app, identifier)
        if runtime is None:
            raise ValueError('The selected app is missing its runtime executable.')
    except (OSError, plistlib.InvalidFileException) as error:
        raise ValueError(f'Cannot read the selected app: {app}. Choose it again.') from error
    return app


def _wine_executable(app):
    identifier = _identifier(app)
    runtime = _resolve_runtime(app, identifier)
    if runtime is None:
        raise ValueError('The selected app is missing its runtime executable.')
    return runtime


def bottle_root(app=None):
    if app is None:
        selected = crossover_app()
    else:
        try:
            selected = validate_app(app)
        except ValueError:
            return Path.home().joinpath(*BOTTLE_ROOTS['com.codeweavers.CrossOver'])
    identifier = _identifier(selected)
    relative = BOTTLE_ROOTS.get(identifier, BOTTLE_ROOTS['com.codeweavers.CrossOver'])
    return Path.home().joinpath(*relative)


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
