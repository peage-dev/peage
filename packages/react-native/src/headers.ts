import { parseAuthenticateError } from '@peage/protocol'

const MEDIA_TYPE_PARAMETER = /^\s*([^=\s]+)\s*=\s*(.*?)\s*$/

function unquote(value: string): string {
  const quoted = /^"(.*)"$/.exec(value) ?? /^'(.*)'$/.exec(value)
  return quoted?.[1] ?? value
}

export function declaredCharsets(contentType: string | null): string[] {
  const parameters = (contentType ?? '').split(';').slice(1)
  return parameters.flatMap((parameter) => {
    const [, name = '', value = ''] = MEDIA_TYPE_PARAMETER.exec(parameter) ?? []
    return name.toLowerCase() === 'charset' ? [unquote(value)] : []
  })
}

export function isUtf8(charset: string): boolean {
  return ['utf-8', 'utf8'].includes(charset.toLowerCase())
}

/** iOS only compresses on exactly `gzip`. */
export function isSupportedContentEncoding(contentEncoding: string): boolean {
  return contentEncoding === 'gzip' || contentEncoding.toLowerCase() === 'identity'
}

export function authenticateErrorOf(response: Response): string | undefined {
  if (response.status !== 401) {
    return undefined
  }
  return parseAuthenticateError(response.headers.get('WWW-Authenticate'))
}
