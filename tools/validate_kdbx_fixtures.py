from __future__ import annotations
import hashlib, json
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
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    assert actual == entry['sha256'], f'SHA-256 mismatch for {path.name}'
    assert entry.get('format') in {'KDBX3', 'KDBX4'}, f'unsupported format label for {path.name}'
    assert isinstance(entry.get('expected'), dict) and entry['expected'], f'missing expected content for {path.name}'
print(f'validated {len(entries)} KDBX fixture(s)')
