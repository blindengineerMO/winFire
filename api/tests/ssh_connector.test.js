import test from 'node:test'
import assert from 'node:assert/strict'
import {parseLinuxOsRelease,parseIptablesRules,parseUfwRules,sshHostKeyPolicy,parseLinuxGuiSessions} from '../src/sshConnector.js'

test('Linux SSH facts helpers normalize OS and firewall output',()=>{
  const os=parseLinuxOsRelease('NAME="Ubuntu"\nVERSION_ID="24.04"\nPRETTY_NAME="Ubuntu 24.04.1 LTS"')
  assert.equal(os.NAME,'Ubuntu');assert.equal(os.VERSION_ID,'24.04')
  const iptables=parseIptablesRules(':INPUT ACCEPT [0:0]\n-A INPUT -p tcp -s 10.0.0.0/8 --dport 22 -j ACCEPT')
  assert.equal(iptables.length,1);assert.equal(iptables[0].localPort,'22');assert.equal(iptables[0].remoteAddress,'10.0.0.0/8')
  const ufw=parseUfwRules('22/tcp ALLOW IN Anywhere\n80/tcp DENY IN 10.0.0.0/8')
  assert.equal(ufw.length,2);assert.equal(ufw[1].action,'block')
})

test('SSH discovery defaults to accepting keys and exposes fingerprint mode',()=>{
  assert.deepEqual(sshHostKeyPolicy({}),{mode:'accept-any',fingerprint:null})
  assert.deepEqual(sshHostKeyPolicy({hostKeyFingerprint:'SHA256:abc'}),{mode:'verify',fingerprint:'SHA256:abc'})
})

test('Linux desktop session parsing selects local active X11 or Wayland users',()=>{
  const sessions=parseLinuxGuiSessions('Id=3|Name=alice|User=1001|Type=x11|Class=user|State=active|Remote=no|Display=:0|Leader=91\nId=4|Name=root|User=0|Type=wayland|Class=user|State=active|Remote=no|Display=|Leader=92')
  assert.equal(sessions.length,1)
  assert.equal(sessions[0].user,'alice')
  assert.equal(sessions[0].type,'x11')
  assert.equal(parseLinuxGuiSessions('Id=4|Name=root|User=0|Type=wayland|Class=user|State=active|Remote=no').length,0)
})
