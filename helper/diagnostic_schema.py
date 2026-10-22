"""Privacy boundary for native v1 rows; vocabulary mirrors src/diagnostic.inc.

IDs are local to (layer, source, process). Neither IDs across layers nor timestamps
establish causality. This module never parses URLs, bodies or arbitrary JSON.
"""
import re

HOSTS = frozenset({
    *(name + '.xboxlive.com' for name in (
        'profile', 'social', 'peoplehub', 'presence', 'userpresence', 'privacy',
        'achievements', 'multiplayer', 'sessiondirectory', 'userstats', 'statsread',
        'inventory', 'xblmessaging', 'licensing', 'titlehub', 'reputation',
        'device.auth', 'user.auth', 'xsts.auth')),
    'api.minecraftservices.com', 'vex.minecraftservices.com', '83156.playfabapi.com',
})
# Existing helper authentication hosts, also exact (never arbitrary subdomains).
AUTH_HOSTS = frozenset({'login.live.com', 'login.microsoftonline.com'})
OPERATIONS = frozenset('token profile social presence privacy achievements multiplayer '
    'statistics inventory messaging licensing xbox-other minecraft-login minecraft-service '
    'playfab-login-steam playfab-login-xbox playfab-link-xbox playfab-entity-token '
    'playfab-other other async-status'.split())
ERRORS = frozenset('InvalidSteamTicket AccountNotFound SteamNotEnabledForTitle '
    'InvalidContentType InvalidParams InvalidRequest InvalidJSONContent ServiceUnavailable '
    'NotAuthenticated InvalidXboxLiveToken InvalidSignature AccountBanned APIRequestLimitExceeded '
    'BadRequest Unauthorized Forbidden AccessDenied TokenExpired InvalidToken '
    'AuthenticationRequired invalid_grant invalid_request unauthorized ForbiddenOperationException'.split())
ENUMS = {
    'layer': {'token', 'http', 'native'},
    'build': {'20261022.1', '20261022.2'},
    'source': {'curl', 'native-http'},
    'coverage': {'pending', 'registered', 'module-missing', 'exports-missing', 'registration-failed', 'disabled'},
    'event': {'start', 'complete', 'result', 'failure', 'coverage'},
    'method': {'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'other'},
    'refresh': {'0', '1'}, 'signature': {'absent', 'present', 'unknown'},
    'response': {'empty', 'json', 'markup', 'other', 'unobserved'},
    'correlation': {'exact', 'unavailable'},
}
NUMBERS = {'id': (0, 2**64-1), 'http': (0, 599),
           'curl': (-2**31, 2**31-1), 'elapsed_ms': (0, 2**63-1),
           'error_code': (-2**31, 2**31-1), 'retry': (0, 2**31-1)}
ORDER = ('v', 'layer', 'event', 'id', 'host', 'operation', 'method', 'refresh',
         'signature', 'hr', 'http', 'curl', 'elapsed_ms', 'error', 'error_code',
         'response', 'request_id', 'retry', 'correlation', 'source', 'coverage', 'build')
ENVELOPE = re.compile(r'^\[t=([0-9]{13}) p=([0-9]{1,10}) th=([0-9]{1,10})\] ')


def parse(line):
    """Require the version/discriminators; validate optional fields independently.

    Reject duplicates and malformed tokens rather than choose ambiguous evidence.
    Unknown keys are discarded, never copied into rejection diagnostics.
    """
    if not line.startswith('diag '):
        return None
    fields = {}
    for part in line[5:].split(' '):
        if not part or '=' not in part:
            return None
        key, value = part.split('=', 1)
        if key in fields or not re.fullmatch(r'[a-z_]+', key) or not value:
            return None
        fields[key] = value
    if (fields.get('v') != '1' or fields.get('layer') not in ENUMS['layer']
            or fields.get('event') not in ENUMS['event']):
        return None
    safe = {'v': '1'}
    for key, value in fields.items():
        if key in ENUMS and value in ENUMS[key]:
            safe[key] = value
        elif key in NUMBERS and re.fullmatch(r'-?[0-9]{1,20}', value):
            low, high = NUMBERS[key]
            if low <= int(value) <= high:
                safe[key] = str(int(value))
        elif key in {'host', 'operation', 'error'}:
            choices = {'host': HOSTS | AUTH_HOSTS | {'other'},
                       'operation': OPERATIONS, 'error': ERRORS | {'none', 'other'}}[key]
            safe[key] = value if value in choices else 'other'
        elif key == 'hr' and re.fullmatch(r'[0-9A-F]{8}', value):
            safe[key] = value
        elif key == 'request_id' and (value == 'absent' or re.fullmatch(
                r'[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}', value)):
            safe[key] = value
    return safe


def render(row):
    text = 'diag ' + ' '.join(key + '=' + row[key] for key in ORDER if key in row)
    # Explicit indicators include values already normalized by the C producer.
    for key in ('host', 'operation', 'error'):
        if row.get(key) == 'other':
            text += ' ' + key + '_unknown=1'
    return text


def coverage(entries, reports):
    """Describe only exported evidence, with no cross-layer or time-based joins."""
    layers = {layer: {'rows': 0, 'starts': 0, 'terminal_rows': 0, 'observation_rows': 0,
                      'unknown_host_rows': 0, 'unknown_operation_rows': 0,
                      'unknown_error_rows': 0} for layer in ('token', 'http', 'native')}
    started, completed = set(), set()
    unscoped_starts = {'token': 0, 'http': 0, 'native': 0}
    failures = 0
    http_sources = {source: {'observation_rows': 0, 'coverage_rows': 0, 'coverage_states': {}, 'events': {}}
                    for source in ('curl', 'native-http', 'unspecified')}
    for name in ('runtime.log', 'http.log'):
        for line in entries.get('logs/' + name, b'').decode().splitlines():
            envelope = ENVELOPE.match(line)
            row = parse(line[envelope.end():] if envelope else line)
            if row is None:
                # Legacy failures have no request correlation either.
                if name == 'runtime.log' and 'Native async failure after user login 0x' in line:
                    failures += 1
                continue
            layer = row['layer']
            summary = layers[layer]
            summary['rows'] += 1
            summary['observation_rows'] += row['event'] != 'coverage'
            if layer == 'http':
                source_summary = http_sources[row.get('source', 'unspecified')]
                counts = source_summary['events']
                counts[row['event']] = counts.get(row['event'], 0) + 1
                if row['event'] == 'coverage':
                    source_summary['coverage_rows'] += 1
                    if 'coverage' in row:
                        states = source_summary['coverage_states']
                        states[row['coverage']] = states.get(row['coverage'], 0) + 1
                else:
                    source_summary['observation_rows'] += 1
            for key in ('host', 'operation', 'error'):
                summary['unknown_' + key + '_rows'] += row.get(key) == 'other'
            identity = (layer, row.get('source', 'unspecified'), int(envelope[2]), row['id']) if envelope and 'id' in row else None
            if row['event'] == 'start':
                summary['starts'] += 1
                if identity is not None:
                    started.add(identity)
                else:
                    unscoped_starts[layer] += 1
            if row['event'] in {'complete', 'result', 'failure'}:
                summary['terminal_rows'] += 1
                if identity is not None:
                    completed.add(identity)
            if layer == 'native' and (row['event'] == 'failure' or
                    'hr' in row and int(row['hr'], 16) & 0x80000000):
                failures += 1
    for layer, summary in layers.items():
        summary['status'] = 'observed' if summary['observation_rows'] else 'unobserved'
        summary['missing_terminal_identities'] = sum(key[0] == layer for key in started - completed)
        summary['starts_without_process_identity'] = unscoped_starts[layer]
    for summary in http_sources.values():
        summary['status'] = 'observed' if summary['observation_rows'] else 'unobserved'
    return {
        'scope': 'exported structured rows only; legacy rows do not establish structured coverage',
        'capture_completeness': 'unknown',
        'layers': layers,
        'missing_or_unobserved': [label for layer, label in
            (('http', 'HTTP requests'), ('token', 'token requests')) if not layers[layer]['observation_rows']],
        'uncorrelated_native_failure_observations': failures,
        'http_sources': http_sources,
        'correlation': 'unavailable across layers; identities are layer+source+pid+id; timestamps never establish causation',
        'field_semantics': {
            'terminal_rows': 'Count of complete, result and failure rows, not final requests or unique failures. Native HTTP result callbacks describe individual attempts before possible retries.',
            'missing_terminal_identities': 'Started identities without any complete, result or failure row in the exported evidence; a matching result does not prove final request completion.',
            'native_http_retry': 'Zero-based observed callback ordinal for this HTTP call, not an authoritative retry count. Missing means unobserved or tracking unavailable.',
            'native_http_hr': 'Network HRESULT when getters succeed; otherwise a getter failure. Independent of HTTP status, so hr=00000000 may accompany http=403.',
            'native_http_error_code': 'Signed int32 platform error bit pattern, not Xbox XErr or an inferred service error.',
            'correlation_exact': 'Producer identity within layer+source+pid only; never a link to a token request or parent native async failure.',
            'coverage_states': 'Counts of historical registration observations, not current registration status. registered does not guarantee current capture or registration after library teardown/reinitialization.',
            'coverage_pending': 'Worker registration is pending; no successful registration or observed request is implied. Deferred registration can miss the first request and other early requests.',
            'recording_coverage': 'Coverage is limited to rows present in this export. New recordings do not inherit archived registration observations. Producer suppression may omit repeated states; absent coverage rows do not establish whether the observer is registered.',
        },
        'limitations': 'Native failure counts are async-status observations, not unique failed requests. Observation can be partial even after registered: deferred worker registration can miss early requests, and library teardown/reinitialization can invalidate registration. Observed rows do not prove complete capture. Missing rows may reflect disabled logging, uninstrumented calls, filtering or bounded input. Process IDs may be reused across runs.',
        'input_capped': any(report['input_capped'] for report in reports.values()),
        'omitted_rows': sum(report['omitted_rows'] for report in reports.values()),
    }
