import type { ServerLocation } from './types.ts'

import { assertAbsolutePath, assertSameOrigin, assertValidBaseUrl } from './asserters.ts'

function splitUrl(url: string): { origin: string; path: string } {
  const origin = /^[a-z][a-z0-9+.-]*:\/\/[^/?#]*/i.exec(url)?.[0] ?? ''
  return { origin, path: url.slice(origin.length) }
}

function normalizeOrigin(origin: string): string {
  const lowercase = origin.toLowerCase()
  if (lowercase.startsWith('https://') && lowercase.endsWith(':443')) {
    return lowercase.slice(0, -':443'.length)
  }
  if (lowercase.startsWith('http://') && lowercase.endsWith(':80')) {
    return lowercase.slice(0, -':80'.length)
  }
  return lowercase
}

export function serverLocationOf(baseUrl: string): ServerLocation {
  const { origin, path } = splitUrl(baseUrl)
  assertValidBaseUrl(origin, path)
  return { origin, basePath: path }
}

export function normalizeBaseUrl(server: ServerLocation): string {
  return normalizeOrigin(server.origin) + server.basePath.replace(/\/+$/, '')
}

/** Characters no HTTP stack re-encodes; Android re-encodes `'` in queries. */
const PATH_CHARACTER = /^[A-Za-z0-9\-._~!$&()*+,;=:@/]$/
const QUERY_CHARACTER = /^[A-Za-z0-9\-._~!$&()*+,;=:@/?]$/
const PERCENT_ESCAPE = /^%[0-9A-Fa-f]{2}$/
const ESCAPE_OR_CHARACTER = /%[0-9A-Fa-f]{2}|[\s\S]/gu

function percentEncodeCharacter(character: string): string {
  const bytes = [...new TextEncoder().encode(character)]
  return bytes.map((byte) => `%${byte.toString(16).toUpperCase().padStart(2, '0')}`).join('')
}

function percentEncode(text: string, allowed: RegExp): string {
  return text.replace(ESCAPE_OR_CHARACTER, (match) =>
    PERCENT_ESCAPE.test(match) || allowed.test(match) ? match : percentEncodeCharacter(match),
  )
}

function isDotSegment(segment: string): boolean {
  return /^(\.|%2e)$/i.test(segment)
}

function isDoubleDotSegment(segment: string): boolean {
  return /^(\.|%2e){2}$/i.test(segment)
}

function removeDotSegments(pathname: string): string {
  const segments = pathname.split('/').slice(1)
  const kept: string[] = []
  for (const segment of segments) {
    if (isDoubleDotSegment(segment)) {
      kept.pop()
    } else if (!isDotSegment(segment)) {
      kept.push(segment)
    }
  }
  const lastSegment = segments.at(-1) ?? ''
  if (isDotSegment(lastSegment) || isDoubleDotSegment(lastSegment)) {
    kept.push('')
  }
  return `/${kept.join('/')}`
}

function normalizePath(path: string): string {
  const [withoutFragment = ''] = path.split('#')
  const queryStart = withoutFragment.indexOf('?')
  const pathname = queryStart === -1 ? withoutFragment : withoutFragment.slice(0, queryStart)
  const query = queryStart === -1 ? '' : withoutFragment.slice(queryStart)
  return (
    percentEncode(removeDotSegments(pathname), PATH_CHARACTER) +
    percentEncode(query, QUERY_CHARACTER)
  )
}

export function serverPathOf(url: string, server: ServerLocation): string {
  const target = splitUrl(url)
  if (!target.origin) {
    assertAbsolutePath(url)
    return normalizePath(`${server.basePath}${url}`)
  }
  assertSameOrigin(normalizeOrigin(target.origin), normalizeOrigin(server.origin))
  return normalizePath(target.path.startsWith('/') ? target.path : `/${target.path}`)
}
