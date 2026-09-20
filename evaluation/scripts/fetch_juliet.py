#!/usr/bin/env python3
"""Fetch the pinned public SARD archive and extract only the selected CWE-457 cases."""
import argparse
import csv
import hashlib
from pathlib import Path, PurePosixPath
import shutil
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
URL = 'https://samate.nist.gov/SARD/downloads/test-suites/2017-11-02-juliet-c-cplusplus-v1-3.zip'
SHA256 = 'a6ddc14bcc11983ad2082d250154bfdd8756cfaa8d151113e8061c12af97aa02'


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--archive', type=Path, required=True, help='existing archive or download destination')
    p.add_argument('--out', type=Path, required=True, help='new extraction directory')
    args = p.parse_args()
    if not args.archive.exists():
        args.archive.parent.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(URL) as src, args.archive.open('xb') as dst:
            shutil.copyfileobj(src, dst)
    h = hashlib.sha256()
    with args.archive.open('rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    if h.hexdigest() != SHA256:
        raise SystemExit('archive SHA-256 mismatch; extraction refused')
    args.out.mkdir(parents=True, exist_ok=False)
    with (ROOT / 'manifests/juliet.tsv').open() as f:
        selected = {r['case_id'] for r in csv.DictReader(f, delimiter='\t')}
    found = set()
    with zipfile.ZipFile(args.archive) as z:
        for member in z.infolist():
            path = PurePosixPath(member.filename)
            if path.is_absolute() or '..' in path.parts or not path.parts or path.parts[0] not in selected:
                continue
            found.add(path.parts[0])
            dst = args.out.joinpath(*path.parts)
            if member.is_dir():
                dst.mkdir(parents=True, exist_ok=True)
            else:
                dst.parent.mkdir(parents=True, exist_ok=True)
                with z.open(member) as src, dst.open('xb') as out:
                    shutil.copyfileobj(src, out)
    if found != selected:
        raise SystemExit(f'missing {len(selected - found)} selected case directories')
    print(f'Extracted {len(found)} selected case pairs; flow variant 12 excluded.')


if __name__ == '__main__':
    main()
