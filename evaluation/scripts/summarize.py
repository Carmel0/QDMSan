#!/usr/bin/env python3
"""Summarize capability-run TSV files as a Markdown table."""
import argparse
import collections
import csv
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('results', nargs='+', type=Path)
    args = parser.parse_args()
    counts = collections.defaultdict(collections.Counter)
    seen = set()
    for path in args.results:
        with path.open() as f:
            for r in csv.DictReader(f, delimiter='\t'):
                key = (r['tool'], r['suite'], r['group'], r['variant'])
                identity = (r['tool'], r['suite'], r['case'], r['opt'], r['variant'])
                if identity in seen:
                    parser.error('duplicate result: ' + str(identity))
                seen.add(identity)
                category = r['category']
                if category == 'CRASH_OR_TIMEOUT' and r['tool'] in ('QDMSan', 'QD-State'):
                    category = 'CRASH' if r['rc'] == '3' else 'TIMEOUT'
                counts[key][category] += 1
    print('| Tool | Suite | Group | Variant | Programs | UUM/reports | Clean | Crashes | Other |')
    print('| --- | --- | --- | --- | --- | --- | --- | --- | --- |')
    for key, c in sorted(counts.items()):
        reports = c['UUM_REPORT'] + c['REPORT']
        total = sum(c.values())
        other = total - reports - c['CLEAN'] - c['CRASH']
        print('| ' + ' | '.join(map(str, (*key, total, reports, c['CLEAN'], c['CRASH'], other))) + ' |')
    print('\nThe paper counts QDMSan/QD-State crashes on buggy programs as findings. '
          'Timeouts and other errors remain separate.')


if __name__ == '__main__':
    main()
