"""Runs only in a new user/network namespace; never changes the host firewall."""
import importlib.util
import json
import tempfile
import time
import uuid
s=importlib.util.spec_from_file_location('helper','api/sidecar/linux_containment.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
m.nft(['-f','-'],'add table inet foreign_fixture\nadd chain inet foreign_fixture input { type filter hook input priority 0; policy accept; }\n')
with tempfile.TemporaryDirectory() as directory:
    key=str(uuid.uuid4());data={'id':key,'operation':'containment_start','seconds':120,'protectedCidrs':['10.42.0.100/32','127.0.0.0/8','::1/128']}
    first=m.main(data,directory);assert first['phase']=='applied'
    second=m.main(data,directory);assert first['deadline']==second['deadline']
    assert m.main({'id':key,'operation':'containment_restore'},directory)['phase']=='restored'
    assert m.dump_table('foreign_fixture') is not None
    assert m.main({'id':key,'operation':'containment_restore'},directory)['phase']=='restored'
    key=str(uuid.uuid4());data['id']=key;m.main(data,directory);table='wfcontain_'+uuid.UUID(key).hex
    m.nft(['-f','-'],f'add rule inet {table} inbound tcp dport 4444 drop\n')
    try:m.main({'id':key,'operation':'containment_restore'},directory);raise AssertionError('Concurrent rule was overwritten')
    except RuntimeError as e:assert 'Concurrent' in str(e)
    m.nft(['delete','table','inet',table])
# Exercise actual kernel timeout independently of the controller worker.
table='wfcontain_expiry';m.nft(['-f','-'],m.rules(table,['127.0.0.0/8','::1/128'],2));deadline=time.time()+2
signature=m.signature(m.dump_table(table),deadline);time.sleep(3)
assert signature==m.signature(m.dump_table(table),deadline)
assert not any(r.get('set',{}).get('elem') for r in json.loads(m.nft(['-j','list','set','inet',table,'lease']))['nftables'])
# A longer lease supplied by another writer is not ours to remove.
m.nft(['-f','-'],f'add element inet {table} lease {{ ipv4 timeout 600s }}\n')
try:m.signature(m.dump_table(table),deadline);raise AssertionError('Extended lease accepted')
except RuntimeError as e:assert 'extension' in str(e)
print('Native nftables expiry, idempotent restore, foreign-rule preservation and concurrent-change rejection passed')
