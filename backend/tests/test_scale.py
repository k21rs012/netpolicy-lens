import pytest
from fastapi.testclient import TestClient
from app import main
from app.analysis_context import AnalysisContext
from app.analyzer import build_matrix, effective_policies
from app.matrix_query import build_query_matrix
from app.models import CanonicalConfig, Device, Segment, Policy
from app.reachability import analyze_reachability
from app.response_cache import ResponseCache
from app.storage import SnapshotStore
from app.topology_graph import build_topology_model, _overlap
from test_ecmp import diamond


def synthetic(count=20):
    return [CanonicalConfig(device=Device(id=f'd{i}', hostname=f'd{i}', vendor='vyos', network_os='vyos', source_file=f'{i}.conf'),
        segments=[Segment(id=f'd{i}-{j}', device=f'd{i}', name=f's{j}', type='interface', networks=[f'10.0.{i}.{j * 128}/25']) for j in range(2)],
        policies=[Policy(id=f'p{i}', device=f'd{i}', name='allow', sequence=1, direction='zone', action='permit')]) for i in range(count)]


@pytest.mark.parametrize('protocol', [None, 'tcp'])
def test_window_union_equals_full_and_single_cell(protocol, tmp_path, monkeypatch):
    cfgs = synthetic(3)
    store = SnapshotStore(str(tmp_path / 'scale.db'))
    sid = store.create('scale', [(c.device.source_file, '', c) for c in cfgs])
    monkeypatch.setattr(main, 'store', store)
    client = TestClient(main.app)
    query = {'protocol': protocol} if protocol else {}
    full = client.get('/api/matrix', params=query).json()
    ids = [s['id'] for s in full['segments']]
    collected = []
    for start in range(0, len(ids), 2):
        for end in range(0, len(ids), 2):
            params = [*query.items(), ('limit', 2), ('snapshot_id', sid)]
            params += [('source_ids', x) for x in ids[start:start + 2]]
            params += [('destination_ids', x) for x in ids[end:end + 2]]
            response = client.get('/api/matrix', params=params)
            assert response.status_code == 200
            page = response.json()
            assert len(page['cells']) == 4 and not page['window']['complete']
            assert page['window']['total_cells'] == 36
            assert client.get('/api/matrix', params=params).json() == page
            collected.extend(page['cells'])
    by_pair = lambda cells: {(c['source'], c['destination']): c for c in cells}
    assert by_pair(collected) == by_pair(full['cells'])
    assert client.get(f'/api/matrix/{ids[0]}/{ids[1]}', params=query).json() == by_pair(collected)[ids[0], ids[1]]


def test_window_bounds_and_latest_snapshot_cache(tmp_path, monkeypatch):
    store = SnapshotStore(str(tmp_path / 'scale.db'))
    cfg = synthetic(1)[0]
    old = store.create('old', [('a', '', cfg)])
    monkeypatch.setattr(main, 'store', store)
    client = TestClient(main.app)
    before = client.get('/api/matrix?limit=25').json()
    assert before['window']['complete']
    cfg.policies[0].action = 'deny'
    new = store.create('new', [('a', '', cfg)])
    after = client.get('/api/matrix?limit=25').json()
    assert before['snapshot_id'] == old and after['snapshot_id'] == new
    assert before['cells'] != after['cells']
    assert client.get(f'/api/matrix?limit=25&snapshot_id={old}').json() == before
    for params in [[('limit', 0)], [('limit', 51)], [('source_ids', 'missing')], [('source_ids', cfg.segments[0].id)] * 51]:
        assert client.get('/api/matrix', params=params).status_code == 422


def test_summary_index_preserves_cross_device_bindings_and_order():
    cfgs = synthetic(3)
    cfgs[0].policies[0].src_segments = ['d1-0']
    cfgs[0].policies[0].dst_segments = ['d2-0']
    policies = [p for c in cfgs for p in c.policies]
    segments = {s.id: s for c in cfgs for s in c.segments}
    for cell in build_matrix(cfgs):
        if cell.source == cell.destination:
            continue
        reference = effective_policies(policies, segments[cell.source], segments[cell.destination])
        assert cell.policy_ids == [p.id for p, _, _ in reference]


def test_shared_context_matches_independent_paths_and_is_not_mutated():
    cfgs = diamond()
    context = AnalysisContext(cfgs)
    before = [c.model_dump_json() for c in cfgs]
    for source in context.segments:
        for destination in context.segments:
            ordinary = analyze_reachability(cfgs, source, destination, 'tcp', 443)
            reused = analyze_reachability(cfgs, source, destination, 'tcp', 443, context=context)
            assert reused == ordinary
    assert [c.model_dump_json() for c in cfgs] == before
    assert len(context.graphs) == 1


def test_topology_sweep_matches_pairwise_for_overlaps_and_families():
    cfgs = synthetic(10)
    cfgs[1].segments[0].networks = ['10.0.0.0/24', '2001:db8::/64', 'bad']
    cfgs[2].segments[0].networks = ['10.0.0.32/27', '2001:db8::1/128']
    cfgs[3].segments[0].type = 'local'
    segments = [s for c in cfgs for s in c.segments]
    reference = []
    for i, left in enumerate(segments):
        for right in segments[i+1:]:
            if left.device != right.device and left.type != 'local' and right.type != 'local':
                overlap = _overlap(left, right)
                if overlap:
                    reference.append((f'segment:{left.id}', f'segment:{right.id}', ', '.join(overlap)))
    actual = build_topology_model(cfgs)
    assert [(e.source, e.target, e.label) for e in actual.edges if e.type == 'adjacent'] == reference


def test_cache_byte_and_entry_bounds_and_mutation_isolation():
    cache = ResponseCache(max_bytes=30, max_entries=2)
    cache.put('a', {'x': 1}); cache.put('b', {'x': 2})
    cache.get('a')['x'] = 99
    assert cache.get('a')['x'] == 1
    cache.put('c', {'x': 3})
    assert cache.get('b') is None
    cache.put('big', {'x': 'a' * 50})
    assert cache.get('big') is None and cache.bytes <= 30
    cache.put('a', {'x': 'a' * 15})
    assert cache.bytes <= 30 and len(cache.entries) <= 2


def test_window_evaluates_only_requested_pairs(monkeypatch):
    import app.matrix_query as query
    calls = []
    original = query.analyze_reachability
    def spy(*args, **kwargs):
        calls.append((args[1], args[2], kwargs['context']))
        return original(*args, **kwargs)
    monkeypatch.setattr(query, 'analyze_reachability', spy)
    query.build_query_matrix(synthetic(), 'tcp', 443, source_ids=['d19-0'], destination_ids=['d18-0'])
    assert len(calls) == 1
