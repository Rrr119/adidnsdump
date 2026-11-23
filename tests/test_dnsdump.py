import csv
import json
import os
import time

import pytest

from adidnsdump import dnsdump


def make_records(count, prefix='host', rtype='A', value_tmpl='10.0.{}.{}'):
    records = []
    for index in range(count):
        records.append({
            'name': '%s%d.example.com' % (prefix, index),
            'type': rtype,
            'value': value_tmpl.format(index // 256, index % 256),
        })
    return records


def read_csv(path):
    with open(path, newline='', encoding='utf-8') as handle:
        return list(csv.reader(handle))


def test_parse_record_type_filter_names_and_ids():
    assert dnsdump.parse_record_type_filter(None) is None
    assert dnsdump.parse_record_type_filter('A, aaaa ,CNAME') == {'A', 'AAAA', 'CNAME'}
    assert dnsdump.parse_record_type_filter('1,28') == {'A', 'AAAA'}
    with pytest.raises(ValueError):
        dnsdump.parse_record_type_filter('A,BOGUS')
    with pytest.raises(ValueError):
        dnsdump.parse_record_type_filter('999')


def test_filter_records():
    records = [
        {'name': 'a', 'type': 'A', 'value': '1.1.1.1'},
        {'name': 'b', 'type': 'AAAA', 'value': '::1'},
        {'name': 'c', 'type': 'A', 'value': '2.2.2.2'},
        {'name': 'd', 'type': '?', 'value': '?'},
    ]
    filtered = dnsdump.filter_records(records, {'A'})
    assert [row['name'] for row in filtered] == ['a', 'c']
    assert dnsdump.filter_records(records, None) is records


def test_full_export_is_csv_compatible_and_creates_no_state_without_flag(tmp_path):
    outfile = str(tmp_path / 'records.csv')
    records = make_records(10)
    result = dnsdump.export_records(records, outfile, 'example.com')

    rows = read_csv(outfile)
    assert rows[0] == ['type', 'name', 'value']
    assert len(rows) == 11
    assert rows[1] == ['A', 'host0.example.com', '10.0.0.0']
    assert result['mode'] == 'full'
    assert not os.path.exists(outfile + dnsdump.STATE_SUFFIX)


def test_full_export_matches_original_line_format(tmp_path):
    outfile = str(tmp_path / 'records.csv')
    records = [
        {'name': 'host0', 'type': 'A', 'value': '10.0.0.1'},
        {'name': 'alias', 'type': 'CNAME', 'value': 'host0.example.com.'},
    ]
    dnsdump.export_records(records, outfile, 'example.com')
    with open(outfile, encoding='utf-8') as handle:
        content = handle.read()
    assert content == (
        'type,name,value\n'
        'A,host0,10.0.0.1\n'
        'CNAME,alias,host0.example.com.\n'
    )


def test_incremental_first_run_is_full_export_with_state(tmp_path):
    outfile = str(tmp_path / 'records.csv')
    state_path = str(tmp_path / 'state.json')
    records = make_records(5)
    result = dnsdump.export_records(
        records, outfile, 'example.com', incremental=True, state_path=state_path)

    assert result['mode'] == 'full'
    assert len(read_csv(outfile)) == 6
    state = json.load(open(state_path, encoding='utf-8'))
    assert state['version'] == dnsdump.STATE_VERSION
    assert state['zone'] == 'example.com'
    assert state['record_count'] == 5
    assert len(state['records']) == 5


def test_incremental_detects_added_changed_deleted(tmp_path):
    outfile = str(tmp_path / 'records.csv')
    state_path = str(tmp_path / 'state.json')
    deleted_file = str(tmp_path / 'deleted.csv')
    records = [
        {'name': 'stable', 'type': 'A', 'value': '10.0.0.1'},
        {'name': 'changes', 'type': 'A', 'value': '10.0.0.2'},
        {'name': 'removed', 'type': 'A', 'value': '10.0.0.3'},
        {'name': 'v6', 'type': 'AAAA', 'value': '::1'},
    ]
    dnsdump.export_records(records, outfile, 'example.com',
                           incremental=True, state_path=state_path)

    next_records = [
        {'name': 'stable', 'type': 'A', 'value': '10.0.0.1'},
        {'name': 'changes', 'type': 'A', 'value': '10.0.9.9'},
        {'name': 'new', 'type': 'A', 'value': '10.0.0.4'},
        {'name': 'v6', 'type': 'AAAA', 'value': '::1'},
    ]
    result = dnsdump.export_records(
        next_records, outfile, 'example.com', incremental=True, state_path=state_path,
        include_deleted=True, deleted_file=deleted_file)

    assert result['mode'] == 'incremental'
    assert result['added'] == 1
    assert result['changed'] == 1
    assert result['deleted'] == 1
    assert result['unchanged'] == 2

    rows = read_csv(outfile)
    assert rows[0] == ['type', 'name', 'value']
    identities = {(row[1], row[2]) for row in rows[1:]}
    assert identities == {('changes', '10.0.9.9'), ('new', '10.0.0.4')}

    deleted_rows = read_csv(deleted_file)
    assert deleted_rows[0] == ['type', 'name', 'value']
    assert deleted_rows[1] == ['A', 'removed', '10.0.0.3']

    state = json.load(open(state_path, encoding='utf-8'))
    assert state['record_count'] == 4


def test_incremental_without_deleted_file_skips_deleted_output(tmp_path):
    outfile = str(tmp_path / 'records.csv')
    state_path = str(tmp_path / 'state.json')
    dnsdump.export_records(
        [{'name': 'a', 'type': 'A', 'value': '1.1.1.1'}],
        outfile, 'example.com', incremental=True, state_path=state_path)
    result = dnsdump.export_records(
        [], outfile, 'example.com', incremental=True, state_path=state_path)
    assert result['mode'] == 'incremental'
    assert result['deleted'] == 1
    assert result['deleted_file'] is None
    assert read_csv(outfile) == [['type', 'name', 'value']]


def test_incremental_resets_to_full_when_zone_or_filter_changes(tmp_path):
    outfile = str(tmp_path / 'records.csv')
    state_path = str(tmp_path / 'state.json')
    dnsdump.export_records(
        make_records(3), outfile, 'example.com',
        incremental=True, state_path=state_path, record_types={'A'})

    result = dnsdump.export_records(
        make_records(3), outfile, 'other.example.com',
        incremental=True, state_path=state_path, record_types={'A'})
    assert result['mode'] == 'full'

    result = dnsdump.export_records(
        make_records(3), outfile, 'other.example.com',
        incremental=True, state_path=state_path, record_types={'A', 'AAAA'})
    assert result['mode'] == 'full'


def test_incremental_with_filter_tracks_only_exported_records(tmp_path):
    outfile = str(tmp_path / 'records.csv')
    state_path = str(tmp_path / 'state.json')
    records = [
        {'name': 'a', 'type': 'A', 'value': '1.1.1.1'},
        {'name': 'b', 'type': 'AAAA', 'value': '::1'},
    ]
    dnsdump.export_records(
        dnsdump.filter_records(records, {'A'}), outfile, 'example.com',
        incremental=True, state_path=state_path, record_types={'A'})
    state = json.load(open(state_path, encoding='utf-8'))
    assert state['record_types'] == ['A']
    assert state['record_count'] == 1


def test_corrupt_state_falls_back_to_full_export(tmp_path):
    outfile = str(tmp_path / 'records.csv')
    state_path = str(tmp_path / 'state.json')
    with open(state_path, 'w', encoding='utf-8') as handle:
        handle.write('{not valid json')
    result = dnsdump.export_records(
        make_records(2), outfile, 'example.com',
        incremental=True, state_path=state_path)
    assert result['mode'] == 'full'
    assert len(read_csv(outfile)) == 3


def test_record_key_roundtrip_handles_unicode_and_separators():
    row = {'type': 'CNAME', 'name': 'höst', 'value': 'target.example.com.'}
    assert dnsdump.key_to_row(dnsdump.record_key(row)) == row


def test_parser_exposes_new_options():
    parser = dnsdump.build_parser()
    args = parser.parse_args([
        'dc.example.com', '--incremental', '-t', 'A,AAAA',
        '--state-file', 's.json', '--include-deleted', '--deleted-file', 'd.csv',
    ])
    assert args.incremental is True
    assert args.record_types == 'A,AAAA'
    assert args.state_file == 's.json'
    assert args.include_deleted is True
    assert args.deleted_file == 'd.csv'
    default_args = dnsdump.build_parser().parse_args(['dc.example.com'])
    assert default_args.incremental is False
    assert default_args.record_types is None
    assert default_args.outfile == 'records.csv'


def test_100k_records_full_and_incremental(tmp_path):
    outfile = str(tmp_path / 'records.csv')
    state_path = str(tmp_path / 'state.json')
    deleted_file = str(tmp_path / 'deleted.csv')
    records = make_records(100_000)

    started = time.time()
    result = dnsdump.export_records(
        records, outfile, 'example.com', incremental=True, state_path=state_path)
    first_elapsed = time.time() - started
    assert result['mode'] == 'full'
    assert result['total'] == 100_000

    rows = read_csv(outfile)
    assert len(rows) == 100_001
    assert rows[0] == ['type', 'name', 'value']
    assert rows[1] == ['A', 'host0.example.com', '10.0.0.0']
    assert rows[-1] == ['A', 'host99999.example.com', '10.0.390.159']

    state = json.load(open(state_path, encoding='utf-8'))
    assert len(state['records']) == 100_000

    # Second run: modify one record, add one, delete one.
    changed = list(records)
    changed[50_000] = dict(changed[50_000], value='10.1.1.1')
    del changed[10]
    changed.append({'name': 'hostnew.example.com', 'type': 'A', 'value': '10.2.2.2'})

    started = time.time()
    result = dnsdump.export_records(
        changed, outfile, 'example.com', incremental=True, state_path=state_path,
        include_deleted=True, deleted_file=deleted_file)
    second_elapsed = time.time() - started

    assert result['mode'] == 'incremental'
    assert result['added'] == 1
    assert result['changed'] == 1
    assert result['deleted'] == 1
    assert result['unchanged'] == 99_998

    delta_rows = read_csv(outfile)
    assert len(delta_rows) == 3
    delta_identities = {row[1] for row in delta_rows[1:]}
    assert delta_identities == {'host50000.example.com', 'hostnew.example.com'}
    deleted_rows = read_csv(deleted_file)
    assert deleted_rows[1][1] == 'host10.example.com'

    # A no-change run afterwards must produce an empty delta and stay fast.
    result = dnsdump.export_records(
        changed, outfile, 'example.com', incremental=True, state_path=state_path)
    assert result['added'] == 0
    assert result['changed'] == 0
    assert result['deleted'] == 0
    assert len(read_csv(outfile)) == 1

    print('\n100k full export: %.2fs, incremental diff: %.2fs'
          % (first_elapsed, second_elapsed))
    assert first_elapsed < 30
    assert second_elapsed < 30
