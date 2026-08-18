from __future__ import annotations
import base64, binascii, hashlib, json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'test-fixtures' / 'kdbx'
manifest = json.loads((FIXTURES / 'manifest.json').read_text(encoding='utf-8'))
assert manifest.get('schema') == 1, 'unsupported KDBX fixture manifest schema'
entries = manifest.get('fixtures')
assert isinstance(entries, list) and entries, 'KDBX fixture manifest must not be empty'
for entry in entries:
    path = FIXTURES / entry['file']
    assert path.is_file(), f'missing KDBX fixture: {path}'
    payload = path.read_bytes()
    encoding = entry.get('encoding', 'raw')
    if encoding == 'raw':
        materialized = payload
    elif encoding == 'base64':
        try:
            materialized = base64.b64decode(payload.strip(), validate=True)
        except binascii.Error as exc:
            raise AssertionError(f'invalid base64 fixture encoding for {path.name}: {exc}') from exc
    else:
        raise AssertionError(f'unsupported fixture encoding for {path.name}: {encoding}')
    actual = hashlib.sha256(materialized).hexdigest()
    assert actual == entry['sha256'], f'SHA-256 mismatch for materialized {path.name}'
    assert entry.get('format') in {'KDBX3', 'KDBX4'}, f'unsupported format label for {path.name}'
    if 'expected_failure' in entry:
        assert isinstance(entry['expected_failure'], str) and entry['expected_failure'], f'missing expected failure category for {path.name}'
        assert 'expected' not in entry, f'negative fixture must not declare positive expected content for {path.name}'
    else:
        assert isinstance(entry.get('expected'), dict) and entry['expected'], f'missing expected content for {path.name}'
    keyfile = entry.get('keyfile')
    if keyfile is not None:
        assert isinstance(keyfile, dict), f'invalid keyfile metadata for {path.name}'
        keyfile_path = FIXTURES / keyfile['file']
        assert keyfile_path.is_file(), f'missing keyfile fixture: {keyfile_path}'
        keyfile_payload = keyfile_path.read_bytes()
        assert hashlib.sha256(keyfile_payload).hexdigest() == keyfile['sha256'], f'SHA-256 mismatch for keyfile {keyfile_path.name}'
        assert len(keyfile_payload) == keyfile['size'], f'size mismatch for keyfile {keyfile_path.name}'
        assert keyfile.get('format') in {'raw32'}, f'unsupported keyfile format for {keyfile_path.name}'
        if keyfile['format'] == 'raw32':
            assert len(keyfile_payload) == 32, f'raw32 keyfile must contain exactly 32 bytes: {keyfile_path.name}'
print(f'validated {len(entries)} KDBX fixture(s)')
