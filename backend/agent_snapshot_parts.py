"""Bounded, transactional staging for existing inventory snapshots."""
import hashlib
import json
import re
import time

PART_BYTES = 192 * 1024
MAX_BYTES = 2 * 1024 * 1024
MAX_PARTS = 12
TTL_SEC = 7 * 86400


def ensure_schema(conn):
    conn.execute('''CREATE TABLE IF NOT EXISTS agent_snapshot_parts (
        agent_id TEXT NOT NULL, module TEXT NOT NULL, transfer_id TEXT NOT NULL,
        part_index INTEGER NOT NULL, part_count INTEGER NOT NULL, checksum TEXT NOT NULL,
        fragment TEXT NOT NULL, created_at INTEGER NOT NULL,
        PRIMARY KEY(agent_id,module,transfer_id,part_index))''')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_snapshot_parts_age ON agent_snapshot_parts(created_at)')


def accept_part(conn, agent_id, payload, *, modules, publish):
    """Caller owns the transaction and commits only successful return values."""
    module = payload.get('module')
    transfer_id = payload.get('transfer_id')
    index = payload.get('part_index')
    count = payload.get('part_count')
    checksum = payload.get('checksum')
    fragment = payload.get('fragment')
    invalid = {'ok': False, 'error': 'snapshot_part_invalid'}
    if (not isinstance(module, str) or module not in modules
            or not isinstance(transfer_id, str) or not re.fullmatch(r'[a-f0-9]{32,64}', transfer_id)
            or type(index) is not int or type(count) is not int or not 2 <= count <= MAX_PARTS
            or not 0 <= index < count or not isinstance(checksum, str)
            or not re.fullmatch(r'[a-f0-9]{64}', checksum) or not isinstance(fragment, str)):
        return invalid
    try:
        part_size = len(fragment.encode('utf-8'))
    except UnicodeError:
        return invalid
    if not 0 < part_size <= PART_BYTES:
        return invalid
    now = int(time.time())
    conn.execute('DELETE FROM agent_snapshot_parts WHERE created_at<?', (now - TTL_SEC,))
    params = (agent_id, module, transfer_id)
    existing = conn.execute('''SELECT part_count,checksum FROM agent_snapshot_parts
        WHERE agent_id=? AND module=? AND transfer_id=? LIMIT 1''', params).fetchone()
    if existing is None:
        if index != 0:
            return {'ok': False, 'error': 'snapshot_parts_missing'}
        # Only one unfinished transfer per agent/module; superseded partials
        # must never replace the last published authoritative snapshot.
        conn.execute('DELETE FROM agent_snapshot_parts WHERE agent_id=? AND module=?', params[:2])
    elif existing[0] != count or existing[1] != checksum:
        return invalid
    old = conn.execute('''SELECT fragment FROM agent_snapshot_parts
        WHERE agent_id=? AND module=? AND transfer_id=? AND part_index=?''', (*params, index)).fetchone()
    if old is not None and old[0] != fragment:
        return invalid
    if old is None:
        conn.execute('INSERT INTO agent_snapshot_parts VALUES(?,?,?,?,?,?,?,?)',
                     (*params, index, count, checksum, fragment, now))
    parts = conn.execute('''SELECT part_index,fragment FROM agent_snapshot_parts
        WHERE agent_id=? AND module=? AND transfer_id=? ORDER BY part_index''', params).fetchall()
    if len(parts) < count:
        if index == count - 1:
            return {'ok': False, 'error': 'snapshot_parts_missing'}
        return {'ok': True, 'complete': False}
    if [row[0] for row in parts] != list(range(count)):
        return invalid
    raw = ''.join(row[1] for row in parts).encode('utf-8')
    if len(raw) > MAX_BYTES or hashlib.sha256(raw).hexdigest() != checksum:
        return {'ok': False, 'error': 'snapshot_parts_integrity_failed'}
    try:
        snapshot = json.loads(raw)
    except (ValueError, UnicodeError):
        return invalid
    if not isinstance(snapshot, dict) or snapshot.get('module') != module:
        return invalid
    snapshot['agent_id'] = agent_id
    result = publish(snapshot)
    if not result.get('ok'):
        return result
    conn.execute('DELETE FROM agent_snapshot_parts WHERE agent_id=? AND module=? AND transfer_id=?', params)
    return {'ok': True, 'complete': True}
