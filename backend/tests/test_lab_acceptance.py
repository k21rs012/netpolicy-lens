"""Authored multi-vendor contracts exercise real APIs against a fresh database."""
import importlib.util
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from app import main
from app.storage import SnapshotStore

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('lab_validate', ROOT / 'lab/validate.py')
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)


@pytest.mark.parametrize('scenario', sorted(path.name for path in lab.SCENARIOS.iterdir() if path.is_dir()))
def test_authored_contract(scenario, tmp_path, monkeypatch):
    monkeypatch.setattr(main, 'store', SnapshotStore(str(tmp_path / 'acceptance.db')))
    result = lab.validate_scenario(TestClient(main.app), lab.SCENARIOS / scenario)
    assert result['status'] == 'passed'


def test_native_routeros_exports_match_recorded_packet_observations(tmp_path, monkeypatch):
    # This replays captured evidence; it does not boot a VM during pytest.
    monkeypatch.setattr(main, 'store', SnapshotStore(str(tmp_path / 'native.db')))
    result = lab.validate_native(TestClient(main.app), ROOT / 'lab/evidence/routeros')
    assert result['native_checks'] == 6
