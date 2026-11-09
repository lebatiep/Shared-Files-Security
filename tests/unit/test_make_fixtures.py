import hashlib
import json

import pytest

from tools.make_fixtures import classify, write_cases


@pytest.fixture(scope='module')
def written(tmp_path_factory):
    out = tmp_path_factory.mktemp('fixtures')
    return out, write_cases(out)


def test_every_fixture_stops_at_its_declared_layer(written):
    out, manifest = written
    assert len(manifest) >= 25
    for entry in manifest:
        assert classify((out / entry['file']).read_bytes()) == entry['expected_stop'], entry['file']


def test_manifest_matches_files_on_disk(written):
    out, manifest = written
    assert json.loads((out / 'manifest.json').read_text(encoding='utf-8')) == manifest
    for entry in manifest:
        data = (out / entry['file']).read_bytes()
        assert hashlib.sha256(data).hexdigest() == entry['sha256'] and len(data) == entry['bytes']


@pytest.mark.case('A07')
@pytest.mark.case('A08')
@pytest.mark.case('A09')
@pytest.mark.case('A10')
@pytest.mark.case('A11')
@pytest.mark.case('A12')
def test_deep_faults_reach_the_inner_layer_not_the_signature(written):
    _, manifest = written
    layers = {entry['case']: set() for entry in manifest}
    for entry in manifest:
        layers[entry['case']].add(entry['expected_stop'])
    assert layers['A07'] == {'UNWRAP'}
    assert layers['A08'] == {'UNWRAP_KEY_LENGTH'}
    assert layers['A09'] == layers['A10'] == {'GCM'}
    assert layers['A11'] == layers['A12'] == {'PAYLOAD'}


@pytest.mark.case('A02')
@pytest.mark.case('A03')
@pytest.mark.case('A05')
def test_unsigned_changes_stop_at_the_signature(written):
    _, manifest = written
    for entry in manifest:
        if entry['case'] in ('A02', 'A03', 'A05'):
            assert entry['expected_stop'] == 'SIGNATURE', entry['file']


def test_the_unmodified_package_passes(written):
    out, manifest = written
    good = next(entry for entry in manifest if entry['file'] == 'good.sfile')
    assert classify((out / good['file']).read_bytes()) == 'OK'
