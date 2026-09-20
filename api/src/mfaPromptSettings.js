import {one} from './db.js'

export function mfaPromptSettings(){
  const mode=one("SELECT value FROM app_settings WHERE key='mfa_prompt_failure_mode'")?.value
  const minutes=Number(one("SELECT value FROM app_settings WHERE key='mfa_prompt_fail_open_minutes'")?.value)
  return {failureMode:mode==='open'?'open':'closed',failOpenMinutes:Number.isInteger(minutes)&&minutes>=2&&minutes<=15?minutes:5}
}
