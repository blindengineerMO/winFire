"""Standard-library WinFire metadata reporter. No prompts, arguments or responses are stored."""
import contextlib
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import time
import urllib.parse
import urllib.request
import uuid

FIELDS = {'schemaVersion','eventId','operationId','nodeId','operation','phase','observedAt','startedAt','endedAt','outcome','errorCode','tool','provider','model','responseModel','hostname','sessionId','traceId','spanId','parentSpanId','requestId','processId','processGuid','processStartedAt','durationMs','inputTokens','outputTokens','cost','adapterVersion'}
TAGS = {'operation','errorCode','tool','provider','model','responseModel','sessionId','traceId','spanId','parentSpanId','requestId','processGuid','adapterVersion'}
def stamp():
    return dt.datetime.now(dt.timezone.utc).isoformat().replace('+00:00','Z')
def metadata_only(raw):
    e = {'schemaVersion':1,'eventId':str(uuid.uuid4()),'observedAt':stamp(),'operation':'other'}
    e.update({k:v for k,v in raw.items() if k in FIELDS and v is not None})
    if e['schemaVersion'] != 1:
        raise ValueError('unsupported_schema')
    for k in TAGS:
        if k in e and (not isinstance(e[k],str) or not re.fullmatch(r'[A-Za-z0-9_.:/@-]{1,128}',e[k])):
            raise ValueError('invalid_identifier')
    for k in ('eventId','operationId','nodeId'):
        if k in e and (not isinstance(e[k],str) or not re.fullmatch(r'[A-Za-z0-9_.:@/ -]{1,160}',e[k])):
            raise ValueError('invalid_identifier')
    for k in ('observedAt','startedAt','endedAt','processStartedAt'):
        if k in e:
            parsed=dt.datetime.fromisoformat(e[k].replace('Z','+00:00'))
            if parsed.tzinfo is None: raise ValueError('timezone_required')
            e[k]=parsed.astimezone(dt.timezone.utc).isoformat().replace('+00:00','Z')
    if e.get('phase','complete') not in ('start','end','complete') or e.get('outcome','success') not in ('success','failure','cancelled','incomplete'):
        raise ValueError('invalid_state')
    for k in TAGS | {'eventId','operationId','nodeId'}:
        if isinstance(e.get(k),str) and re.match(r'^(?:sk-(?:ant-|proj-)?[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.)',e[k]): raise ValueError('credential_like_metadata')
    if 'hostname' in e:
        value=str(e['hostname']); host=urllib.parse.urlsplit(value).hostname if '://' in value else value
        if '://' in value and urllib.parse.urlsplit(value).scheme not in ('http','https'): raise ValueError('invalid_host')
        host=host.rstrip('.').encode('idna').decode('ascii').lower()
        if len(host)>253 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',part) for part in host.split('.')): raise ValueError('invalid_host')
        e['hostname']=host
    for k in ('inputTokens','outputTokens','processId','durationMs'):
        if k in e and (isinstance(e[k],bool) or not isinstance(e[k],(int,float)) or e[k]<0): raise ValueError('invalid_metric')
    if 'cost' in e:
        c=e['cost']
        if set(c) != {'amount','currency','source'} or not re.fullmatch(r'\d{1,12}(\.\d{1,9})?',str(c['amount'])) or not re.fullmatch(r'[A-Z]{3}',c['currency']) or not re.fullmatch(r'[A-Za-z0-9_.:/@-]{1,128}',c['source']): raise ValueError('invalid_cost')
    if len(json.dumps(e).encode())>65536: raise ValueError('oversized_report')
    return e

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):
        return None

class AiReporter:
    def __init__(self,base_url=None,credential=None,spool=None,max_queued=1000):
        self.base_url=(base_url or os.environ['WINFIRE_AI_URL']).rstrip('/')
        u=urllib.parse.urlsplit(self.base_url)
        if u.scheme!='https' and not (u.scheme=='http' and u.hostname in ('localhost','127.0.0.1','::1')): raise ValueError('HTTPS required')
        if u.username or u.password or u.query or u.fragment: raise ValueError('Use a clean base URL')
        self.credential=credential or os.environ['WINFIRE_AI_CREDENTIAL']
        self.spool=Path(spool or os.environ.get('WINFIRE_AI_SPOOL',Path.home()/'.winfire'/'ai-spool-python'))
        self.spool.mkdir(mode=0o700,parents=True,exist_ok=True);self.spool.chmod(0o700)
        self.max_queued=max(1,min(10000,max_queued));self.next_attempt=0;self.failures=0
        self.health={'queued':0,'dropped':0,'schemaErrors':0,'adapterVersion':'winfire-python-1'}
    def record(self,raw):
        try: return self._record(raw)
        except OSError:
            self.health['dropped']+=1;return None
    def _record(self,raw):
        if re.search(r'report_ai_usage(?:_batch)?$',raw.get('tool') or ''): return None
        try: e=metadata_only(raw)
        except (ValueError,TypeError,AttributeError,OverflowError):
            self.health['schemaErrors']+=1;return None
        files=list(self.spool.glob('*.json'))
        if len(files)>=self.max_queued: self.health['dropped']+=1;return None
        target=self.spool/(hashlib.sha256(e['eventId'].encode()).hexdigest()+'.json')
        if target.exists(): return e['eventId']
        temp=target.with_suffix('.'+str(uuid.uuid4())+'.tmp')
        fd=os.open(temp,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        with os.fdopen(fd,'w') as f: json.dump(e,f)
        temp.replace(target);self.health['queued']=len(files)+1
        return e['eventId']
    @contextlib.contextmanager
    def track(self,**metadata):
        started=stamp()
        try:
            yield
        except BaseException as exc:
            self.record(dict(metadata,startedAt=started,endedAt=stamp(),outcome='cancelled' if (isinstance(exc,(KeyboardInterrupt,SystemExit)) or type(exc).__name__=='CancelledError') else 'failure',errorCode='operation_failed'))
            raise
        else: self.record(dict(metadata,startedAt=started,endedAt=stamp(),outcome='success'))
    def _post(self,path,data):
        request=urllib.request.Request(self.base_url+path,data=json.dumps(data).encode(),headers={'Authorization':'Bearer '+self.credential,'Content-Type':'application/json'},method='POST')
        with urllib.request.build_opener(NoRedirect()).open(request,timeout=5) as response: return json.load(response)
    def flush(self,force=False):
        if not force and time.time()<self.next_attempt: return {'deferred':True,'results':[]}
        events=[];paths=[]
        try:
            for p in sorted(self.spool.glob('*.json'))[:100]:
                try:
                    if p.is_symlink() or p.stat().st_size>65536: raise ValueError()
                    raw=json.loads(p.read_text())
                    if not raw.get('eventId') or not raw.get('observedAt'): raise ValueError('corrupt_spool')
                    event=metadata_only(raw)
                    if len(json.dumps({'events':events+[event]}).encode())>240*1024: break
                    events.append(event);paths.append(p)
                except (ValueError,OSError,TypeError):
                    self.health['schemaErrors']+=1;p.unlink(missing_ok=True)
            if not events: return {'results':[]}
            receipt=self._post('/api/v1/ai/usage:batch',{'events':events})
            if len(receipt.get('results',[]))!=len(events): raise ValueError('invalid_receipt')
            for event,p,result in zip(events,paths,receipt['results']):
                if result.get('eventId')==event['eventId'] and result.get('status') in ('accepted','duplicate','rejected') and not result.get('retryable'):
                    p.unlink(missing_ok=True)
                    if result['status']=='rejected': self.health['schemaErrors']+=1
            self.failures=0;self.next_attempt=0
            return receipt
        except Exception:
            self.failures+=1;self.next_attempt=time.time()+min(300,2**min(self.failures,8));return {'offline':True,'results':[]}
        finally: self.health['queued']=len(list(self.spool.glob('*.json')))
    def heartbeat(self):
        try: self._post('/api/v1/ai/heartbeat',self.health)
        except Exception: pass
