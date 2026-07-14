import { createReadStream } from 'node:fs'
import { stat } from 'node:fs/promises'
import { createServer } from 'node:http'
import { extname, resolve, sep } from 'node:path'

const root = resolve(process.argv[2])
const contentTypes = {
  '.json': 'application/json; charset=utf-8',
  '.tgz': 'application/gzip',
  '.sha256': 'text/plain; charset=utf-8',
}

const server = createServer(async (request, response) => {
  try {
    const pathname = decodeURIComponent(new URL(request.url ?? '/', 'http://127.0.0.1').pathname)
    const path = resolve(root, `.${pathname}`)
    if (path !== root && !path.startsWith(`${root}${sep}`)) {
      response.writeHead(403).end('forbidden')
      return
    }
    const info = await stat(path)
    if (!info.isFile()) throw new Error('not a file')
    response.setHeader('content-length', String(info.size))
    response.setHeader('content-type', contentTypes[extname(path)] ?? 'application/octet-stream')
    createReadStream(path).pipe(response)
  } catch {
    response.writeHead(404).end('not found')
  }
})

server.listen(0, '127.0.0.1', () => {
  const address = server.address()
  if (!address || typeof address === 'string') throw new Error('could not bind fixture server')
  process.stdout.write(`${address.port}\n`)
})

process.on('SIGTERM', () => server.close())
