"""End-to-end transactional publication using a private in-memory fixture."""
import hashlib
import asyncio
import json
import os
import sqlite3
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from backend import agent_edr, agent_ingest_v2, agent_protocol as ap
from backend.agent_snapshot_parts import ensure_schema


class _FixtureConnection(sqlite3.Connection):
    def close(self):
        # Keep the private in-memory DB alive between batch transactions.
        pass


class PagedAssetPublicationTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(':memory:', factory=_FixtureConnection, check_same_thread=False)
        self.addCleanup(sqlite3.Connection.close, self.conn)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(ap._SCHEMA)
        ap._add_col(self.conn, 'agent_snapshots', 'generation', 'INTEGER DEFAULT 0')
        ap._add_col(self.conn, 'agent_snapshots', 'keys_json', "TEXT DEFAULT ''")
        self.conn.executescript('''CREATE TABLE agent_receipts(agent_id TEXT,event_uuid TEXT,kind TEXT,
            stream TEXT,seq INTEGER,status TEXT,error TEXT,received_at TEXT,PRIMARY KEY(agent_id,event_uuid));
            CREATE TABLE agent_streams(agent_id TEXT,stream TEXT,high_seq INTEGER,received INTEGER,
            rejected INTEGER,updated_at TEXT,PRIMARY KEY(agent_id,stream));''')
        ensure_schema(self.conn)
        self.conn.commit()
        self.enterContext(patch.object(ap, '_real_connect', return_value=self.conn))
        self.enterContext(patch.object(ap, 'ensure_db'))
        self.enterContext(patch.object(agent_edr, 'ensure'))
        self.enterContext(patch.object(ap, 'mark_telemetry_received'))
        self.publish = self.enterContext(patch.object(ap, '_post_snapshot', return_value={'ok': True}))
        self.enterContext(patch.object(agent_ingest_v2, '_purge_receipts'))

    def send(self, uuid, kind, payload):
        return agent_ingest_v2.ingest_batch('fixture', [{'uuid': uuid, 'kind': kind, 'seq': 1, 'payload': payload}])

    def snapshot(self, module):
        return tuple(self.conn.execute('SELECT generation,item_count,payload_json,keys_json FROM agent_snapshots WHERE agent_id=? AND module=?', ('fixture', module)).fetchone())

    def test_snapshot_page_consistency(self):
        keys = [f'fixture-{i}' for i in range(1501)]
        rows = [{'name': key} for key in keys]
        payload = dict(agent_id='fixture', module='software', items=rows, keys=keys,
                       generation=1, paged_software=True)
        self.assertTrue(ap.upsert_snapshot(payload, staged=True)['ok'])
        full = ap.get_snapshot('fixture', 'software')
        self.assertEqual(full['item']['items'], rows)
        page = ap.get_snapshot('fixture', 'software', offset=0, limit=100)
        version = page['page']['snapshot_version']
        joined = []
        while True:
            self.assertEqual(page['page']['total'], len(rows))
            self.assertNotIn('keys_json', page['item'])
            joined.extend(page['item']['items'])
            offset = page['page']['next_offset']
            if offset is None:
                break
            page = ap.get_snapshot('fixture', 'software', offset=offset, limit=100, snapshot_version=version)
            self.assertTrue(page['ok'])
        self.assertEqual(joined, rows)
        self.assertFalse(ap.get_snapshot('fixture', 'software', limit=501)['ok'])
        self.assertTrue(ap.upsert_snapshot(dict(payload, generation=2), staged=True)['ok'])
        self.assertEqual(ap.get_snapshot('fixture', 'software', offset=100, limit=100, snapshot_version=version)['error'], 'snapshot_version_changed')

    def test_complete_publication_and_replay(self):
        for module in ('software', 'service', 'hotfix', 'user'):
            with self.subTest(module=module):
                old = {'module': module, 'items': [{'name': 'old'}], 'keys': ['old'], 'generation': 1}
                self.assertEqual(self.send(f'{module}-old-full', 'snapshot', old)['acked'], [f'{module}-old-full'])
                before = self.snapshot(module)
                keys = [f'{module}-{n}' for n in range(1501)]
                items = [{'name': k} for k in keys]
                payload = dict(module=module, items=items, keys=keys, generation=2)
                payload['paged_software' if module == 'software' else 'paged_inventory'] = True
                raw = json.dumps(payload, ensure_ascii=False)
                midpoint = len(raw) // 2
                checksum = hashlib.sha256(raw.encode()).hexdigest()
                meta = dict(module=module, transfer_id=checksum, part_count=2, checksum=checksum)
                first = dict(meta, part_index=0, fragment=raw[:midpoint])
                second = dict(meta, part_index=1, fragment=raw[midpoint:])
                first_id, second_id = f'{module}-part-one', f'{module}-part-two'
                self.assertEqual(self.send(first_id, 'snapshot_part', first)['acked'], [first_id])
                self.assertEqual(self.snapshot(module), before)
                self.assertEqual(self.send(first_id, 'snapshot_part', first)['duplicates'], 1)
                self.assertEqual(self.snapshot(module), before)
                self.assertEqual(self.send(second_id, 'snapshot_part', second)['acked'], [second_id])
                result = self.snapshot(module)
                self.assertEqual(result[:2], (2, 1501))
                self.assertEqual(json.loads(result[2]), items)
                self.assertEqual(json.loads(result[3]), keys)
                self.assertEqual(self.send(second_id, 'snapshot_part', second)['duplicates'], 1)
                self.assertEqual(self.snapshot(module), result)
                self.assertEqual(self.conn.execute('SELECT COUNT(*) FROM agent_snapshot_parts WHERE module=?', (module,)).fetchone()[0], 0)

    def test_invalid_versioned_snapshot_preserves_previous_publication(self):
        module = 'service'
        old = {'module': module, 'items': [{'name': 'old'}], 'keys': ['old'], 'generation': 1}
        self.assertEqual(self.send('original-full', 'snapshot', old)['acked'], ['original-full'])
        before = self.snapshot(module)
        items = [{'name': f'fixture-{i}'} for i in range(1501)]
        payload = dict(module=module, items=items, keys=['duplicate'] * len(items), generation=2, paged_inventory=True)
        raw = json.dumps(payload)
        midpoint = len(raw) // 2
        checksum = hashlib.sha256(raw.encode()).hexdigest()
        meta = dict(module=module, transfer_id=checksum, part_count=2, checksum=checksum)
        self.assertEqual(self.send('invalid-part-one', 'snapshot_part', dict(meta, part_index=0, fragment=raw[:midpoint]))['acked'], ['invalid-part-one'])
        result = self.send('invalid-part-two', 'snapshot_part', dict(meta, part_index=1, fragment=raw[midpoint:]))
        self.assertEqual(result['acked'], [])
        self.assertEqual(result['rejected'][0]['error'], 'snapshot_keys_invalid')
        self.assertEqual(self.snapshot(module), before)

    def test_paged_snapshot_requires_integer_generation(self):
        module = 'service'
        old = {'module': module, 'items': [{'name': 'old'}], 'keys': ['old'], 'generation': 1}
        self.assertEqual(self.send('generation-old-full', 'snapshot', old)['acked'], ['generation-old-full'])
        before = self.snapshot(module)
        for i, generation in enumerate((None, False, 1.5, '2', 0, -1)):
            with self.subTest(generation=generation):
                keys = [f'fixture-{n}' for n in range(1501)]
                payload = dict(module=module, items=[{'name': key} for key in keys], keys=keys,
                               generation=generation, paged_inventory=True)
                raw = json.dumps(payload)
                split = len(raw) // 2
                checksum = hashlib.sha256(raw.encode()).hexdigest()
                meta = dict(module=module, transfer_id=checksum, part_count=2, checksum=checksum)
                first, last = f'generation-{i}-part-one', f'generation-{i}-part-two'
                self.assertEqual(self.send(first, 'snapshot_part', dict(meta, part_index=0, fragment=raw[:split]))['acked'], [first])
                result = self.send(last, 'snapshot_part', dict(meta, part_index=1, fragment=raw[split:]))
                self.assertEqual(result['acked'], [])
                self.assertEqual(result['rejected'][0]['error'], 'snapshot_generation_invalid')
                self.assertEqual(self.snapshot(module), before)


class InventoryCapacityTests(PagedAssetPublicationTests):
    """Bounded, in-process capacity probe; no network or real endpoints."""
    def test_synthetic_inventory_capacity(self):
        for count in (100, 500, 1000):
            with self.subTest(endpoints=count):
                prefix = f'capacity-{count}-'
                def publish(index):
                    aid = prefix + str(index)
                    uid = 'synthetic-snapshot-' + str(index)
                    body = {'uuid': uid, 'kind': 'snapshot', 'seq': 1, 'payload': {
                        'module': 'software', 'items': [{'name': 'fixture-package'}],
                        'keys': ['fixture-package'], 'generation': 1}}
                    started = time.perf_counter()
                    result = agent_ingest_v2.ingest_batch(aid, [body])
                    return result['acked'] == [uid] and not result['rejected'], time.perf_counter() - started

                started = time.perf_counter()
                with ThreadPoolExecutor(max_workers=8) as pool:
                    results = list(pool.map(publish, range(count)))
                elapsed = time.perf_counter() - started
                self.assertTrue(all(ok for ok, _ in results))
                latencies = sorted(seconds for _, seconds in results)
                self.assertEqual(self.conn.execute('SELECT COUNT(*) FROM agent_snapshots WHERE agent_id LIKE ?', (prefix + '%',)).fetchone()[0], count)
                self.assertEqual(self.conn.execute('SELECT COUNT(*) FROM agent_receipts WHERE agent_id LIKE ?', (prefix + '%',)).fetchone()[0], count)
                print(f'synthetic_endpoints={count} workers=8 seconds={elapsed:.3f} p95_ms={1000*latencies[int((count-1)*.95)]:.2f} accepted={count}')


class PagedAssetRouteTests(PagedAssetPublicationTests):
    """Call the real route with a private request fixture and real auth guard."""
    def setUp(self):
        super().setUp()
        self.credential = ap.SECRET_PREFIX + 'test-only-fixture-secret'
        self.enterContext(patch.object(ap, 'verify_agent_secret', side_effect=lambda aid, token:
            'ok' if aid == 'fixture' and token == self.credential else 'invalid'))

    def request(self, credential):
        from starlette.requests import Request
        return Request({'type': 'http', 'headers': [(b'authorization', ('Bearer ' + credential).encode()),
                                                    (b'x-agent-id', b'fixture')]})

    def send(self, uuid, kind, payload):
        from backend.edr_api import api_agent_v2_batch
        return api_agent_v2_batch(self.request(self.credential), {'agent_id': 'fixture',
            'events': [{'uuid': uuid, 'kind': kind, 'seq': 1, 'payload': payload}]})

    def test_invalid_test_credential_rejected(self):
        from fastapi import HTTPException
        from backend.edr_api import api_agent_v2_batch
        with self.assertRaises(HTTPException) as result:
            api_agent_v2_batch(self.request(ap.SECRET_PREFIX + 'invalid-fixture'), {'agent_id': 'fixture', 'events': []})
        self.assertEqual(result.exception.status_code, 401)
        self.assertEqual(self.conn.execute('SELECT COUNT(*) FROM agent_snapshots').fetchone()[0], 0)

    def test_snapshot_read_route_version_conflict(self):
        from fastapi import HTTPException
        from backend import agent_telemetry_api as api
        payload = {'agent_id': 'fixture', 'module': 'software', 'items': [{'name': 'fixture'}],
                   'keys': ['fixture'], 'generation': 1}
        self.assertTrue(ap.upsert_snapshot(payload)['ok'])
        with patch.object(api, '_require_user', return_value={'id': 'fixture-user'}) as auth:
            result = api.api_agent_snapshot_get('fixture', 'software', self.request(self.credential), 0, 100, None)
            self.assertEqual(result['item']['items'], payload['items'])
            version = result['page']['snapshot_version']
            self.assertTrue(ap.upsert_snapshot(dict(payload, generation=2))['ok'])
            with self.assertRaises(HTTPException) as raised:
                api.api_agent_snapshot_get('fixture', 'software', self.request(self.credential), 0, 100, version)
            self.assertEqual(raised.exception.status_code, 409)
            self.assertEqual(auth.call_count, 2)


@unittest.skipUnless(os.getenv('EDR_HTTP_ACCEPTANCE') == '1', 'opt-in ASGI HTTP acceptance')
class PagedAssetHTTPTests(PagedAssetPublicationTests):
    """Exercise the real HTTP route and auth guard with a fixture credential."""
    def setUp(self):
        super().setUp()
        from fastapi import FastAPI
        from backend import edr_api

        self.credential = ap.SECRET_PREFIX + 'test-only-fixture-secret'
        self.enterContext(patch.object(ap, 'verify_agent_secret', side_effect=lambda aid, token:
            'ok' if aid == 'fixture' and token == self.credential else 'invalid'))
        self.app = FastAPI()
        self.app.include_router(edr_api.router)

    def post(self, credential, payload):
        import httpx

        async def request():
            # Native ASGI transport avoids the deprecated Starlette TestClient
            # adapter and never opens an external HTTP connection.
            transport = httpx.ASGITransport(app=self.app)
            async with httpx.AsyncClient(transport=transport, base_url='http://testserver') as client:
                return await client.post('/api/agent/v2/events/batch',
                    headers={'Authorization': 'Bearer ' + credential, 'X-Agent-Id': 'fixture'}, json=payload)

        return asyncio.run(request())

    def send(self, uuid, kind, payload):
        response = self.post(self.credential, {'agent_id': 'fixture', 'events': [{'uuid': uuid, 'kind': kind, 'seq': 1, 'payload': payload}]})
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def test_invalid_test_credential_rejected(self):
        response = self.post(ap.SECRET_PREFIX + 'invalid-fixture',
            {'agent_id': 'fixture', 'events': [{'uuid': 'fixture-rejected', 'kind': 'snapshot', 'seq': 1,
                'payload': {'module': 'service', 'items': [{'name': 'fixture'}]}}]})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.conn.execute('SELECT COUNT(*) FROM agent_snapshots').fetchone()[0], 0)
