// Mask strings/comments before inspecting the module envelope, preserving line breaks.
// This is not the ASN.1 parser; net-snmp compiles definitions in the worker.
export function mibEnvelope(text){
  let out='',inString=false,inComment=false
  for(let i=0;i<text.length;i++){
    const char=text[i],next=text[i+1]
    if(inComment){
      if(char==='\n'||char==='\r'){inComment=false;out+=char}
      else if(char==='-'&&next==='-'){inComment=false;out+='  ';i++}
      else out+=' '
    }else if(inString){
      if(char==='"'&&next==='"'){out+='  ';i++}
      else if(char==='\\'&&next){out+='  ';i++}
      else if(char==='"'){inString=false;out+=' '}
      else out+=char==='\n'||char==='\r'?char:' '
    }else if(char==='-'&&next==='-'){inComment=true;out+='  ';i++}
    else if(char==='"'){inString=true;out+=' '}
    else out+=char
  }
  if(inString)throw new Error('Unterminated string in MIB source')
  return out
}
export const mibModuleName=text=>mibEnvelope(text).match(/\b([A-Za-z][\w-]*)\s+DEFINITIONS\s*::=\s*BEGIN/)?.[1]
