"""Bounded, incident-owned nftables containment. No existing table is flushed."""
import base64
import datetime
import fcntl
import hashlib
import ipaddress
import json
import os
import pathlib
import subprocess
import sys
import time
import uuid


def nft(arguments, content=None):
    result = subprocess.run(['nft', *arguments], input=content, text=True, capture_output=True, timeout=20)
    if result.returncode:
        raise RuntimeError('nftables operation failed: ' + result.stderr[:500])
    return result.stdout


def dump_table(table):
    tables = json.loads(nft(['-j', 'list', 'tables']))['nftables']
    if not any(t.get('table', {}).get('name') == table and t.get('table', {}).get('family') == 'inet' for t in tables):
        return None
    return json.loads(nft(['-j', 'list', 'table', 'inet', table]))


def signature(snapshot, deadline):
    # Kernel expiry removes lease elements. Compare the remaining table structure,
    # while rejecting a changed or extended lease rather than deleting it.
    def clean(value):
        if isinstance(value, list):
            return [clean(v) for v in value if not isinstance(v, dict) or 'metainfo' not in v]
        if not isinstance(value, dict):
            return value
        result = {}
        for key, item in value.items():
            if key in ('handle', 'expires'):
                if key == 'expires' and item > max(0, deadline-time.time())+3:
                    raise RuntimeError('Concurrent lease extension prevents restore')
                continue
            if key == 'elem':
                # Only our two protocol values may occur in the lease set.
                for element in item if isinstance(item, list) else [item]:
                    raw = element.get('elem', element) if isinstance(element, dict) else element
                    val = raw.get('val') if isinstance(raw, dict) else raw
                    if val not in ('ipv4', 'ipv6', 2, 10):
                        raise RuntimeError('Unexpected lease element prevents restore')
                    if isinstance(raw, dict) and raw.get('expires', 0) > max(0, deadline-time.time())+3:
                        raise RuntimeError('Concurrent lease extension prevents restore')
                continue
            result[key] = clean(item)
        return result
    return hashlib.sha256(json.dumps(clean(snapshot), sort_keys=True).encode()).hexdigest()


def rules(table, cidrs, seconds):
    lines = [f'add table inet {table}', f'add set inet {table} lease {{ type nf_proto; flags timeout; timeout {seconds}s; elements = {{ ipv4, ipv6 }}; }}']
    for direction, hook, address, interface in [('inbound', 'input', 'saddr', 'iifname'), ('outbound', 'output', 'daddr', 'oifname')]:
        lines.append(f'add chain inet {table} {direction} {{ type filter hook {hook} priority -20; policy accept; }}')
        lines.append(f'add rule inet {table} {direction} {interface} "lo" return')
        for cidr in cidrs:
            family = 'ip' if ipaddress.ip_network(cidr).version == 4 else 'ip6'
            lines.append(f'add rule inet {table} {direction} {family} {address} {cidr} return')
        lines.append(f'add rule inet {table} {direction} meta nfproto @lease drop')
    return '\n'.join(lines)+'\n'


def main(data, state_directory='/var/lib/winfire/containment'):
    if os.geteuid() != 0:
        raise RuntimeError('Passwordless sudo/root and nftables are required')
    key = uuid.UUID(data['id']).hex
    table = 'wfcontain_'+key
    directory = pathlib.Path(state_directory)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if directory.is_symlink() or directory.stat().st_uid != 0 or directory.stat().st_mode & 0o022:
        raise RuntimeError('Recovery state directory is not root-owned and private')
    state_path = directory/(key+'.json')
    lock_path = directory/(key+'.lock')
    def save(state):
        temporary = state_path.with_suffix('.tmp')
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as output:
            json.dump(state, output)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, state_path)
    with os.fdopen(os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600), 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        state = json.loads(state_path.read_text()) if state_path.exists() else None
        current = dump_table(table)
        if data['operation'] == 'containment_restore':
            if current is None:
                result = {'phase': 'restored', 'nativeRecovery': True}
                save(result)
                return result
            if not state or not state.get('signature') or signature(current, state['deadline']) != state['signature']:
                raise RuntimeError('Concurrent or unknown table changes require review; native lease expiry remains active')
            nft(['delete', 'table', 'inet', table])
            if dump_table(table) is not None:
                raise RuntimeError('Containment table still exists')
            state['phase'] = 'restored'
            save(state)
            return state
        if data['operation'] != 'containment_start':
            raise RuntimeError('Unsupported operation')
        if state:
            # Never renew a lease after a lost reply or restart.
            if state.get('phase') == 'applied' and current and signature(current, state['deadline']) == state.get('signature'):
                if time.time() >= state['deadline']:
                    raise RuntimeError('Containment lease expired; restore before another incident')
                return state
            raise RuntimeError('Existing containment transaction requires restoration')
        if current is not None:
            raise RuntimeError('Incident table already exists')
        seconds = int(data['seconds'])
        if not 120 <= seconds <= 3600:
            raise RuntimeError('Invalid containment duration')
        cidrs = [str(ipaddress.ip_network(v, strict=False)) for v in data['protectedCidrs']]
        if not 1 <= len(cidrs) <= 256:
            raise RuntimeError('Invalid protected dependency scope')
        ruleset=json.loads(nft(['-j', 'list', 'ruleset']))
        if any('flowtable' in row for row in ruleset['nftables']):
            raise RuntimeError('Flow offload requires a separate containment adapter')
        content = rules(table, cidrs, seconds)
        nft(['--check', '-f', '-'], content)
        deadline = time.time()+seconds
        state = {'phase': 'applying', 'deadline': deadline, 'nativeRecovery': True, 'expiresAt': datetime.datetime.fromtimestamp(deadline, datetime.timezone.utc).isoformat()}
        save(state)
        nft(['-f', '-'], content)
        current = dump_table(table)
        if current is None:
            raise RuntimeError('Containment readback failed')
        state.update(phase='applied', signature=signature(current, deadline))
        save(state)
        return state


if __name__ == '__main__':
    try:
        print(json.dumps(main(json.loads(base64.b64decode(sys.argv[1])))))
    except Exception as error:
        print(str(error)[:1000], file=sys.stderr)
        sys.exit(1)
