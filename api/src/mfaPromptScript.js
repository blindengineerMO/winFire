import fs from 'node:fs'
import path from 'node:path'
import {fileURLToPath} from 'node:url'
export const mfaPromptFunctions=fs.readFileSync(path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../../packages/shared/mfaPrompt.ps1'),'utf8')
