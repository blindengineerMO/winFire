// Response contracts shared by generated API documentation and API clients.
const text={type:'string'},nullableText={type:['string','null']},integer={type:'integer'},flag={type:'boolean'}
const strings={type:'array',items:text}
const ref=name=>({$ref:`#/components/schemas/${name}`})
const object=(properties,required=[])=>({type:'object',properties,required})
export const internetConnectionSchemas={
  InternetBoundary:object({revision:{type:['integer','null']},desiredRevision:integer,pending:flag,cursor:integer,highWater:integer,cidrs:strings,configuredCidrs:strings,configurationNeeded:flag,missingFamilies:{type:'array',items:{type:'integer',enum:[4,6]}}},['pending','cidrs','configurationNeeded']),
  InternetConnection:object({
    id:text,event_id:text,windows_event_id:integer,node_id:nullableText,node_hostname:nullableText,
    observed_at:{type:'string',format:'date-time'},revision:integer,original_revision:integer,original_scope:{type:'string',enum:['outside','not-outside']},
    source_ip:text,destination_ip:text,source_port:{type:['integer','null']},destination_port:{type:['integer','null']},local_ip:nullableText,peer_ip:text,peer_id:nullableText,
    direction:{type:'string',enum:['in','out','unknown']},attribution:{type:'string',enum:['reporting-node-address','legacy-inbound-corrected','forwarded-local-endpoint','cidr-endpoint','reported-direction-roaming','ambiguous']},
    action:nullableText,protocol:nullableText,program:nullableText,category:text,outside:{type:'integer',enum:[0,1]},
    ptrNames:strings,hostnameSource:{const:'reverse-dns'},dns_status:nullableText,dns_checked_at:nullableText,dns_error:nullableText,dnsStale:flag,
    observation:text,provenance:{const:'firewall-event'},activitiesUrl:text,mappingUrl:text
  },['id','event_id','peer_ip','direction','ptrNames','provenance']),
  InternetConnectionSummary:object({events:integer,peers:integer,allowed:integer,blocked:integer,scope:ref('InternetBoundary')},['events','peers','allowed','blocked','scope']),
  InternetConnectionPage:object({items:{type:'array',items:ref('InternetConnection')},total:integer,page:integer,limit:integer,pages:integer,summary:ref('InternetConnectionSummary')},['items','total','page','limit','pages','summary']),
  InternetConnectionExport:object({items:{type:'array',maxItems:10000,items:ref('InternetConnection')},total:integer,scope:ref('InternetBoundary')},['items','total','scope']),
  InternetPeer:object({id:text,ip:text,resolver_context:text,first_seen_at:text,last_seen_at:text,names:strings,hostnameSource:{const:'reverse-dns'},status:{type:'string',enum:['pending','resolved','not-found','error','stale']},stale:flag,checked_at:nullableText,last_success_at:nullableText,next_lookup_at:nullableText,error:nullableText,attempts:integer,
    cachePolicy:object({positiveHours:integer,negativeHours:integer,timeoutMs:integer,concurrency:integer,retentionDays:integer}),
    observedNames:{type:'array',items:text,description:'Only separately observed evidence; never inferred from PTR.'},
    history:{type:'array',maxItems:100,items:object({checked_at:text,status:text,names:strings,error:nullableText})}
  },['id','ip','names','hostnameSource','status','stale']),
  InternetConnectionDetails:{allOf:[ref('InternetConnection'),object({scope:ref('InternetBoundary'),peer:ref('InternetPeer'),event:{type:'object',additionalProperties:true,description:'Original retained event, with compacted fields resolved.'},observedNames:strings,ruleEligible:flag,ignoreEligible:flag,mappingReferences:strings},['event','scope','ruleEligible','ignoreEligible','mappingReferences'])]},
  InternetDnsEnqueue:object({queued:{const:true},coalesced:flag},['queued','coalesced'])
}
