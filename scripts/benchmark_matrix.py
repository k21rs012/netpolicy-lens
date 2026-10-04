"""Reproducible synthetic benchmark; does not touch snapshots or live devices.

Run: .venv312/bin/python scripts/benchmark_matrix.py --devices 100 --full
"""
import argparse
import json
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'backend'))
from app.analyzer import build_matrix
from app.matrix_query import build_query_matrix
from app.models import CanonicalConfig, Device, Policy, Segment
from app.topology_graph import build_topology_model


def synthetic(count):
    return [CanonicalConfig(
        device=Device(id=f'd{i}', hostname=f'd{i}', vendor='vyos', network_os='vyos', source_file=f'{i}.conf'),
        segments=[Segment(id=f'd{i}-{j}', device=f'd{i}', name=f's{j}', type='interface',
                          networks=[f'10.{i // 256}.{i % 256}.{j * 128}/25']) for j in range(2)],
        policies=[Policy(id=f'p{i}', device=f'd{i}', name='permit', sequence=1,
                         direction='zone', src=['any'], dst=['any'], action='permit')],
    ) for i in range(count)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--devices', type=int, default=100)
    parser.add_argument('--full', action='store_true', help='also evaluate every pair (quadratic output size)')
    args = parser.parse_args()
    if not 1 <= args.devices <= 65536:
        parser.error('--devices must be 1..65536')
    configs = synthetic(args.devices)
    selected = [s.id for c in configs for s in c.segments][:25]
    operations = [('topology', lambda: build_topology_model(configs)),
                  ('summary_window', lambda: build_matrix(configs, selected, selected)),
                  ('conditioned_window', lambda: build_query_matrix(configs, 'tcp', 443,
                                             source_ids=selected, destination_ids=selected))]
    if args.full:
        operations += [('summary_full', lambda: build_matrix(configs)),
                       ('conditioned_full', lambda: build_query_matrix(configs, 'tcp', 443))]
    for name, operation in operations:
        start = time.perf_counter()
        result = operation()
        print(json.dumps({'devices': args.devices, 'segments': args.devices * 2, 'operation': name,
                          'seconds': round(time.perf_counter() - start, 4),
                          'cells': len(result) if isinstance(result, list) else None}), flush=True)


if __name__ == '__main__':
    main()
