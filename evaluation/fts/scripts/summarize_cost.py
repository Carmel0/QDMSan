#!/usr/bin/env python3
"""Summarize detector slowdowns using a median of ratios paired within rounds."""
import argparse
import json
import math
from pathlib import Path
import statistics

ARMS = ('plain', 'shm', 'qd', 'qmsan', 'memcheck')
COLUMNS = ('memcheck', 'qmsan', 'shm', 'qd')


def read_recorded(path):
    rounds = {}
    in_table = False
    for line in path.read_text().splitlines():
        if line.startswith('| Round | Target | Inputs |'):
            in_table = True
            continue
        if not in_table:
            continue
        if not line.startswith('|'):
            break
        cells = [c.strip() for c in line.strip('|').split('|')]
        if not cells[0].isdigit():
            continue
        if len(cells) != 8:
            raise ValueError('expected eight columns in the round-median table')
        rnd, target, count = int(cells[0]), cells[1], int(cells[2])
        group = rounds.setdefault(rnd, {})
        if target in group:
            raise ValueError(f'duplicate round/target: {rnd}/{target}')
        group[target] = {'n_inputs': count, **dict(zip(ARMS, map(float, cells[3:])))}
    if not rounds:
        raise ValueError('no round-median table found')
    return list(rounds.values())


def read_round(path):
    result = {}
    targets = None
    for arm in ARMS:
        groups = {}
        rows = json.loads((path / f'cost_{arm}.json').read_text())
        for row in rows:
            group = groups.setdefault(row['target'], [])
            if any(r['rep'] == row['rep'] for r in group):
                raise ValueError('duplicate repetition')
            group.append(row)
        if targets is None:
            targets = set(groups)
        elif set(groups) != targets:
            raise ValueError('target sets differ between detectors')
        for target, group in groups.items():
            counts = {r['n_inputs'] for r in group}
            if len(counts) != 1:
                raise ValueError('input counts differ between repetitions')
            n = counts.pop()
            record = result.setdefault(target, {'n_inputs': n})
            if record['n_inputs'] != n:
                raise ValueError('input counts differ between detectors')
            record[arm] = statistics.median(r['wall_s'] for r in group)
    return result


def summarize(rounds):
    targets = list(rounds[0])
    for rnd in rounds:
        if set(rnd) != set(targets):
            raise ValueError('target sets differ between rounds')
        for target in targets:
            if rnd[target]['n_inputs'] != rounds[0][target]['n_inputs']:
                raise ValueError('input counts differ between rounds')
            if any(rnd[target][arm] <= 0 for arm in ARMS):
                raise ValueError('elapsed times must be positive')
    result = {target: [statistics.median(rnd[target][a] / rnd[target]['plain']
                                        for rnd in rounds) for a in COLUMNS]
              for target in targets}
    result['Overall'] = [math.exp(statistics.mean(math.log(v[i]) for v in result.values()))
                         for i in range(len(COLUMNS))]
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--rounds', nargs='+', type=Path, help='output directory for each complete round')
    source.add_argument('--recorded', type=Path, help='Markdown file containing the recorded round medians')
    args = parser.parse_args()
    try:
        rounds = read_recorded(args.recorded) if args.recorded else [read_round(p) for p in args.rounds]
        result = summarize(rounds)
    except (ValueError, OSError, KeyError) as exc:
        parser.error(str(exc))
    print('| Target | Memcheck | QMSan accurate | QDMSan single run | QDMSan full check |')
    print('| --- | --- | --- | --- | --- |')
    for target, ratios in result.items():
        print('| ' + target + ' | ' + ' | '.join(f'{x:.2f}x' for x in ratios) + ' |')
    print(f'\nMedian of within-round ratios over {len(rounds)} rounds; '
          'Overall is the geometric mean across targets.')


if __name__ == '__main__':
    main()
