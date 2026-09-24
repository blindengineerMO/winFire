// Curated read-only collection plans. Vendor source files are imported by the operator.
const table=(name,oid)=>({name,oid,kind:'table'})
const scalar=(name,oid)=>({name,oid,kind:'scalar'})
const profile=(moduleName,description,objects,match={},sourceUrl='')=>({moduleName,description,objects,match,sourceUrl})
export const builtinMibProfiles=[
  profile('IF-MIB','Interface names, status, speed, MAC addresses and 64-bit counters',[table('ifTable','1.3.6.1.2.1.2.2'),table('ifXTable','1.3.6.1.2.1.31.1.1')],{all:true},'https://www.rfc-editor.org/info/rfc2863/'),
  profile('ENTITY-MIB','Chassis, serial numbers, models and hardware/firmware revisions',[table('entPhysicalTable','1.3.6.1.2.1.47.1.1.1')],{all:true},'https://www.rfc-editor.org/info/rfc4133/'),
  profile('HOST-RESOURCES-MIB','Memory, processors, storage and system devices',[scalar('hrMemorySize','1.3.6.1.2.1.25.2.2.0'),table('hrStorageTable','1.3.6.1.2.1.25.2.3'),table('hrDeviceTable','1.3.6.1.2.1.25.3.2'),table('hrProcessorTable','1.3.6.1.2.1.25.3.3')],{all:true},'https://www.rfc-editor.org/info/rfc2790/'),
  profile('IP-MIB','IPv4/IPv6 neighbor cache and address inventory',[table('ipNetToPhysicalTable','1.3.6.1.2.1.4.35'),table('ipAddressTable','1.3.6.1.2.1.4.34')],{all:true},'https://www.rfc-editor.org/info/rfc4293/'),
  profile('IP-FORWARD-MIB','Modern IPv4/IPv6 routing table',[table('inetCidrRouteTable','1.3.6.1.2.1.4.24.7')],{all:true},'https://www.rfc-editor.org/info/rfc4292/'),
  profile('TCP-MIB','Modern IPv4/IPv6 TCP connections and listeners',[table('tcpConnectionTable','1.3.6.1.2.1.6.19'),table('tcpListenerTable','1.3.6.1.2.1.6.20')],{all:true},'https://www.rfc-editor.org/info/rfc4022/'),
  profile('Q-BRIDGE-MIB','VLAN-aware forwarding database and current VLANs',[table('dot1qTpFdbTable','1.3.6.1.2.1.17.7.1.2.2'),table('dot1qVlanCurrentTable','1.3.6.1.2.1.17.7.1.4.2')],{all:true},'https://www.rfc-editor.org/info/rfc4363/'),
  profile('LLDP-MIB','Remote system names, capabilities and connected ports',[table('lldpRemTable','1.0.8802.1.1.2.1.4.1')],{all:true},'https://www.ieee802.org/1/pages/802.1ab.html'),
  profile('CISCO-ENVMON-MIB','Cisco temperatures, fans, power supplies and voltage sensors',[table('ciscoEnvMonVoltageStatusTable','1.3.6.1.4.1.9.9.13.1.2'),table('ciscoEnvMonTemperatureStatusTable','1.3.6.1.4.1.9.9.13.1.3'),table('ciscoEnvMonFanStatusTable','1.3.6.1.4.1.9.9.13.1.4'),table('ciscoEnvMonSupplyStatusTable','1.3.6.1.4.1.9.9.13.1.5')],{sysObjectIdPrefixes:['1.3.6.1.4.1.9'],sysDescrContains:['cisco']},'https://github.com/cisco/cisco-mibs/blob/main/v2/CISCO-ENVMON-MIB.my'),
  profile('BEGEMOT-PF-MIB','PF state counters, interfaces and tables (requires the PF module)',[table('pfStatistics','1.3.6.1.4.1.12325.1.200')],{sysDescrContains:['pfsense','opnsense']},'https://docs.netgate.com/pfsense/en/latest/services/snmp.html'),
  profile('MIKROTIK-MIB','RouterOS system identity, licensing and hardware health',[table('mtxrSystem','1.3.6.1.4.1.14988.1.1.4'),table('mtxrHealth','1.3.6.1.4.1.14988.1.1.3')],{sysObjectIdPrefixes:['1.3.6.1.4.1.14988'],sysDescrContains:['routeros','mikrotik']},'https://help.mikrotik.com/docs/spaces/ROS/pages/8978519/SNMP'),
  profile('VMWARE-SYSTEM-MIB','VMware product name, version and build',[scalar('vmwProdName','1.3.6.1.4.1.6876.1.1.0'),scalar('vmwProdVersion','1.3.6.1.4.1.6876.1.2.0'),scalar('vmwProdBuild','1.3.6.1.4.1.6876.1.4.0')],{sysObjectIdPrefixes:['1.3.6.1.4.1.6876'],sysDescrContains:['vmware','esxi']},'https://knowledge.broadcom.com/external/article?legacyId=2145018'),
  profile('SNWL-COMMON-MIB','SonicWall model, firmware and serial identity',[table('sonicwallSystem','1.3.6.1.4.1.8741.2.1.1')],{sysObjectIdPrefixes:['1.3.6.1.4.1.8741'],sysDescrContains:['sonicwall','sonicos']},'https://www.sonicwall.com/support/knowledge-base/sonicwall-oid-values-from-the-mib-files/kA1VN0000000HVZ0A2'),
  profile('NS-ROOT-MIB','NetScaler system statistics',[table('nsSysGroup','1.3.6.1.4.1.5951.4.1.1')],{sysObjectIdPrefixes:['1.3.6.1.4.1.5951'],sysDescrContains:['netscaler','citrix adc']},'https://docs.netscaler.com/en-us/citrix-adc/current-release/system/snmp.html')
]

export const mibTableColumns={
  entPhysicalTable:{2:'entPhysicalDescr',4:'entPhysicalContainedIn',5:'entPhysicalClass',7:'entPhysicalName',8:'entPhysicalHardwareRev',9:'entPhysicalFirmwareRev',10:'entPhysicalSoftwareRev',11:'entPhysicalSerialNum',12:'entPhysicalMfgName',13:'entPhysicalModelName'},
  ifTable:{1:'ifIndex',2:'ifDescr',3:'ifType',4:'ifMtu',5:'ifSpeed',6:'ifPhysAddress',7:'ifAdminStatus',8:'ifOperStatus',9:'ifLastChange',10:'ifInOctets',16:'ifOutOctets'},
  ifXTable:{1:'ifName',6:'ifHCInOctets',10:'ifHCOutOctets',15:'ifHighSpeed',18:'ifAlias'},
  hrStorageTable:{2:'hrStorageType',3:'hrStorageDescr',4:'hrStorageAllocationUnits',5:'hrStorageSize',6:'hrStorageUsed'},
  hrDeviceTable:{2:'hrDeviceType',3:'hrDeviceDescr',5:'hrDeviceStatus'},
  hrProcessorTable:{2:'hrProcessorLoad'},
  ipNetToPhysicalTable:{1:'ipNetToPhysicalIfIndex',2:'ipNetToPhysicalNetAddressType',3:'ipNetToPhysicalNetAddress',4:'ipNetToPhysicalPhysAddress',6:'ipNetToPhysicalType',7:'ipNetToPhysicalState'},
  dot1qTpFdbTable:{1:'dot1qTpFdbAddress',2:'dot1qTpFdbPort',3:'dot1qTpFdbStatus'},
  lldpRemTable:{4:'lldpRemChassisIdSubtype',5:'lldpRemChassisId',6:'lldpRemPortIdSubtype',7:'lldpRemPortId',8:'lldpRemPortDesc',9:'lldpRemSysName',10:'lldpRemSysDesc',11:'lldpRemSysCapSupported',12:'lldpRemSysCapEnabled'}
}
export function collectedObjectName(object,oid){
  if(!oid.startsWith(object.oid+'.1.'))return object.name
  return mibTableColumns[object.name]?.[oid.slice(object.oid.length+3).split('.')[0]]||object.name
}
