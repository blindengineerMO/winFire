import test from 'node:test'
import assert from 'node:assert/strict'
import {existsSync} from 'node:fs'
import {spawnSync} from 'node:child_process'

const python=existsSync('.venv/bin/python')?'.venv/bin/python':'python3'
const available=spawnSync(python,['-c','import impacket,winrm'],{encoding:'utf8'}).status===0

test('WMI stages a bounded read script, parses rule frames, and removes remote files',{skip:!available},()=>{
  const code=String.raw`
import base64,json,re,sys
sys.path.insert(0,'api/sidecar')
import wmi_probe

class Result:
    def getProperties(self):return {'ReturnValue':{'value':0},'ProcessId':{'value':1234}}
    def RemRelease(self):pass
class Process:
    def Create(self,command,directory,environment):
        assert 'powershell.exe' in command and '-File' in command
        return Result()
    def RemRelease(self):pass
class Services:
    def GetObject(self,name):
        assert name=='Win32_Process'
        return Process(),None
class SMB:
    def __init__(self,*args,**kwargs):self.deleted=[]
    def login(self,*args):pass
    def putFile(self,share,path,reader):
        assert share=='ADMIN$' and path.endswith('.ps1')
        self.script=reader().decode('utf-8-sig')
        self.marker=re.search(r'DONE\|([0-9a-f]{32})',self.script).group(1)
        assert 'Get-WinFireLegacyRules' in self.script or 'Write-WinFireEvent' in self.script or "Out-Field 'NAME'" in self.script or 'Get-WinFireAuditSetting' in self.script
    def getFile(self,share,path,writer):
        if 'Set-WinFireLegacyRules $group $add $remove' in self.script:
            writer(('APPLIED|true\nDONE|'+self.marker+'\n').encode())
        elif "$mode='event_cursor'" in self.script:
            writer(('CURSOR|23\nDONE|'+self.marker+'\n').encode())
        elif "$mode='events'" in self.script:
            xml='<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>5157</EventID><TimeCreated SystemTime="2026-09-20T16:00:00.0000000Z"/><EventRecordID>24</EventRecordID></System><EventData><Data Name="SourceAddress">192.0.2.5</Data><Data Name="DestPort">3389</Data></EventData></Event>'
            writer(('EVENT|'+base64.b64encode(xml.encode()).decode()+'\nDONE|'+self.marker+'\n').encode())
        elif "Out-Field 'NAME'" in self.script:
            values={'NAME':'TEST-NODE','VERSION':'10.0.20348','DOMAIN':'example.test'}
            writer(('\n'.join(key+'='+base64.b64encode(value.encode()).decode() for key,value in values.items())+'\nDONE|'+self.marker+'\n').encode())
        elif 'Get-WinFireAuditSetting' in self.script:
            writer(('AUDIT|3\nDONE|'+self.marker+'\n').encode())
        else:
            values=['WinFireSecure:test:wf:abc','Test','WinFireSecure:test','True','allow','in','TCP','3389','Any','Any','Any','Domain']
            fields='|'.join(base64.b64encode(value.encode()).decode() for value in values)
            writer(('HEADER|1|0\nRULE|'+fields+'\nDONE|'+self.marker+'\n').encode())
    def deleteFile(self,share,path):self.deleted.append(path)
    def logoff(self):pass
smb=SMB()
wmi_probe.SMBConnection=lambda *args,**kwargs:smb
wmi_probe.time.sleep=lambda seconds:None
result=wmi_probe.run_staged_operation(Services(),'192.0.2.1','reader','secret','EXAMPLE','all_rules','10.0.20348',{'offset':0,'limit':100})
assert result['total']==1 and result['rules'][0]['name']=='Test'
assert len(smb.deleted)==2 and any(path.endswith('.ps1') for path in smb.deleted) and any(path.endswith('.txt') for path in smb.deleted)
class DeniedProcess(Process):
    def Create(self,command,directory,environment):
        class DeniedResult(Result):
            def getProperties(self):return {'ReturnValue':{'value':5}}
        return DeniedResult()
class DeniedServices(Services):
    def GetObject(self,name):return DeniedProcess(),None
try:wmi_probe.run_staged_operation(DeniedServices(),'192.0.2.1','reader','secret','EXAMPLE','all_rules','10.0.20348',{})
except RuntimeError as error:assert 'returned 5' in str(error)
else:raise AssertionError('WMI process creation failure was accepted')
assert len(smb.deleted)==4
assert wmi_probe.run_staged_operation(Services(),'192.0.2.1','reader','secret','EXAMPLE','apply','10.0.20348',{'group':'WinFireSecure:test','add':[],'remove':[]})=={'applied':True}
assert len(smb.deleted)==6
assert wmi_probe.run_staged_operation(Services(),'192.0.2.1','reader','secret','EXAMPLE','event_cursor','10.0.20348',{})==23
events=wmi_probe.run_staged_operation(Services(),'192.0.2.1','reader','secret','EXAMPLE','events','10.0.20348',{'after':23})
assert events[0]['RecordId']==24 and events[0]['Id']==5157 and events[0]['Fields']['DestPort']=='3389'
assert len(smb.deleted)==10
facts=wmi_probe.run_staged_operation(Services(),'192.0.2.1','reader','secret','EXAMPLE','facts','10.0.20348',{})
assert facts['computer']['Name']=='TEST-NODE' and facts['os']['Version']=='10.0.20348'
assert len(smb.deleted)==12
audit=wmi_probe.run_staged_operation(Services(),'192.0.2.1','reader','secret','EXAMPLE','audit_policy','10.0.20348',{})
assert audit['settingValue']==3 and audit['successEnabled'] and audit['failureEnabled']
assert wmi_probe.run_staged_operation(Services(),'192.0.2.1','reader','secret','EXAMPLE','audit_policy_enable','10.0.20348',{})==audit
assert len(smb.deleted)==16
assert 'Get-WinFireXpRules' in wmi_probe.firewall_script('all_rules','5.1.2600',{},'a'*32)
assert "Get-WinFireXpEvents 'events' 0" in wmi_probe.firewall_script('events','5.1.2600',{},'a'*32)
try:wmi_probe.firewall_script('rules','5.1.2600',{'group':'WinFireSecure:test'},'a'*32)
except RuntimeError:pass
else:raise AssertionError('XP accepted managed firewall readback')
print(json.dumps({'rules':result['total'],'deleted':len(smb.deleted),'events':len(events)}))
`
  const result=spawnSync(python,['-c',code],{encoding:'utf8',timeout:10000})
  assert.equal(result.status,0,result.stderr)
  assert.deepEqual(JSON.parse(result.stdout),{rules:1,deleted:16,events:1})
})
