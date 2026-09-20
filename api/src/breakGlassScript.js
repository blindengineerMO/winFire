import fs from 'node:fs'
import path from 'node:path'
import {fileURLToPath} from 'node:url'

const source=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../../packages/shared/breakGlass.ps1')
export const breakGlassFunctions=fs.readFileSync(source,'utf8')
