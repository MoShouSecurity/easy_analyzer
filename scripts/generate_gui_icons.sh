#!/usr/bin/env bash
set -euo pipefail

icon_root="$(cd "$(dirname "$0")/.." && pwd)"
icon_cli="$icon_root/crates/analyzer-gui/frontend/node_modules/.bin/tauri"
if [[ ! -x "$icon_cli" ]]; then
  echo "Install frontend dependencies before generating icons: npm --prefix crates/analyzer-gui/frontend ci --ignore-scripts" >&2
  exit 1
fi
# Rebuild from the vendored SVG masters; no dependency on the shared design library.
python3 - "$icon_root" "$icon_cli" <<'PY'
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile

root, cli = Path(sys.argv[1]), sys.argv[2]
dest = root / 'crates/analyzer-gui/icons/easy-family'
sizes = [16, 24, 32, 48, 64, 128, 256, 512, 1024]
ico_sizes = sizes[:7]

def render(source, output, png_sizes=()):
    command = [cli, 'icon', str(source), '--output', str(output)]
    for size in png_sizes:
        command += ['--png', str(size)]
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(result.stderr or result.stdout)

with tempfile.TemporaryDirectory(prefix='easy-analyzer-icons-') as temporary:
    stage = Path(temporary)
    render(dest / 'icon.svg', stage / 'desktop')
    render(dest / 'icon.svg', stage / 'regular', sizes)
    render(dest / 'icon-micro.svg', stage / 'micro', [16, 24, 32])
    # Stable chunk order makes repeated ICNS exports byte-identical.
    icns = (stage / 'desktop/icon.icns').read_bytes()
    assert icns[:4] == b'icns' and int.from_bytes(icns[4:8], 'big') == len(icns)
    chunks, cursor = [], 8
    while cursor < len(icns):
        length = int.from_bytes(icns[cursor + 4:cursor + 8], 'big')
        assert length >= 8 and cursor + length <= len(icns)
        chunks.append(icns[cursor:cursor + length])
        cursor += length
    assert not any(chunk[:4] == b'TOC ' for chunk in chunks), 'Unexpected ICNS table of contents'
    (dest / 'icon.icns').write_bytes(icns[:8] + b''.join(sorted(chunks, key=lambda chunk: chunk[:4])))
    # Preserve independently rendered small frames; resizing loses micro adjustments.
    frames = []
    for size in ico_sizes:
        folder = 'micro' if size <= 32 else 'regular'
        data = (stage / folder / f'{size}x{size}.png').read_bytes()
        assert data[:8] == b'\x89PNG\r\n\x1a\n'
        assert struct.unpack_from('>II', data, 16) == (size, size)
        assert data[25] == 6  # RGBA PNG
        frames.append(data)
    offset = 6 + 16 * len(frames)
    entries = []
    for size, data in zip(ico_sizes, frames):
        entries.append(struct.pack('<BBBBHHII', size % 256, size % 256, 0, 0, 1, 32, len(data), offset))
        offset += len(data)
    (dest / 'icon.ico').write_bytes(struct.pack('<HHH', 0, 1, len(frames)) + b''.join(entries) + b''.join(frames))
    # Only persist resources referenced by Tauri; other sizes stay temporary.
    for source, name in [
        ('micro/32x32.png', '32x32.png'),
        ('regular/128x128.png', '128x128.png'),
        ('regular/256x256.png', '128x128@2x.png'),
    ]:
        shutil.copyfile(stage / source, dest / name)
public = root / 'crates/analyzer-gui/frontend/public'
public.mkdir(parents=True, exist_ok=True)
shutil.copyfile(dest / 'icon-micro.svg', public / 'easy-analyzer.svg')
print(f'Desktop icons: {dest}')
PY
