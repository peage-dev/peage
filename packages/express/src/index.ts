import type { NextFunction, Request, RequestHandler, Response } from 'express'

import {
  assertPlatform,
  createPeage as createCorePeage,
  type Peage,
  PeageError,
  type PeageErrorCode,
  type VerifiedRequest,
} from '@peage/core'
import {
  type AuthenticateError,
  CHALLENGE_PATH,
  formatAuthenticateHeader,
  fromBase64url,
  HTTP_HEADER_ASSERTION,
  HTTP_HEADER_KEY_ID,
  SOLVE_PATH,
} from '@peage/protocol'

import type { PeageExpress, PeageExpressConfig } from './types.ts'

import {
  assertBodyUnread,
  assertHttpAuthority,
  assertJsonObject,
  assertUnpaddedBase64url,
  assertValidMaxBodyBytes,
  assertValidSolveRequest,
  assertVerifiedByProtect,
} from './asserters.ts'
import { readDecodedBodyBounded, readIdentityBodyBounded } from './body.ts'
import { HttpStatusError } from './errors.ts'

export { PeageError } from '@peage/core'
export { CHALLENGE_PATH, SOLVE_PATH }
export type {
  AppAttestConfig,
  AttestationEnvironment,
  AttestedKeyRecord,
  IssuedChallenge,
  KeyAttestationConfig,
  LoadRevokedSerialNumbers,
  Peage,
  PeageConfig,
  PeageErrorCode,
  PeageEvent,
  PeageStore,
  PlayIntegrityConfig,
  RegistrationRequest,
  SignedRequest,
  VerifiedRequest,
} from '@peage/core'
export type { Platform } from '@peage/protocol'
export type { PeageExpress, PeageExpressConfig } from './types.ts'

type AsyncMiddleware = (req: Request, res: Response, next: NextFunction) => Promise<void>

declare global {
  namespace Express {
    interface Locals {
      /** Set by `protect` once the request is verified. */
      peage?: VerifiedRequest
    }
  }
}

const DEFAULT_MAX_BODY_BYTES = 1024 * 1024
const PROTOCOL_MAX_BODY_BYTES = 128 * 1024
const ABSOLUTE_FORM = /^([A-Za-z][A-Za-z0-9+.-]*):\/\/([^/?#]*)([\s\S]*)$/

type ErrorResponse = { status: number; authenticateError?: AuthenticateError }

const RESPONSE_BY_CODE: Record<PeageErrorCode, ErrorResponse> = {
  REQUEST_MALFORMED: { status: 400 },
  PLATFORM_DISABLED: { status: 400 },
  CHALLENGE_UNKNOWN: { status: 401, authenticateError: 'unknown_challenge' },
  ATTESTATION_INVALID: { status: 401, authenticateError: 'invalid_attestation' },
  KEY_UNKNOWN: { status: 401, authenticateError: 'unknown_key' },
  SIGNATURE_INVALID: { status: 401, authenticateError: 'invalid_signature' },
}

function responseFor(error: unknown): ErrorResponse | undefined {
  if (error instanceof HttpStatusError) {
    return { status: error.status }
  }
  if (error instanceof PeageError) {
    return RESPONSE_BY_CODE[error.code]
  }
  return undefined
}

function closeConnectionIfBodyPending(req: Request, res: Response): void {
  if (!req.complete) {
    res.setHeader('Connection', 'close')
  }
}

function withHttpErrors(handler: AsyncMiddleware): RequestHandler {
  return async (req, res, next) => {
    try {
      await handler(req, res, next)
    } catch (error) {
      closeConnectionIfBodyPending(req, res)
      const response = responseFor(error)
      if (response === undefined) {
        next(error)
        return
      }
      if (response.status === 401) {
        res.setHeader('WWW-Authenticate', formatAuthenticateHeader(response.authenticateError))
      }
      res.status(response.status).end()
    }
  }
}

function readRequiredHeader(req: Request, name: string): string {
  const value = req.header(name)
  if (!value) {
    throw new HttpStatusError(401)
  }
  return value
}

function decodeBase64url(value: string): Uint8Array {
  assertUnpaddedBase64url(value)
  return fromBase64url(value)
}

function pathAndQueryOf(absoluteForm: RegExpExecArray): string {
  const [, scheme = '', authority = '', pathAndQuery = ''] = absoluteForm
  assertHttpAuthority(scheme, authority)
  if (pathAndQuery === '' || pathAndQuery.startsWith('?')) {
    return `/${pathAndQuery}`
  }
  return pathAndQuery
}

function originFormOf(requestTarget: string): string {
  const absoluteForm = ABSOLUTE_FORM.exec(requestTarget)
  return absoluteForm ? pathAndQueryOf(absoluteForm) : requestTarget
}

function parseJson(bytes: Uint8Array): unknown {
  try {
    return JSON.parse(Buffer.from(bytes).toString('utf8'))
  } catch {
    throw new HttpStatusError(400)
  }
}

async function readJsonObject(req: Request): Promise<Record<string, unknown>> {
  const body: unknown =
    req.body !== undefined
      ? req.body
      : parseJson(await readIdentityBodyBounded(req, PROTOCOL_MAX_BODY_BYTES))
  assertJsonObject(body)
  return body
}

function challengeHandler(peage: Peage): RequestHandler {
  return withHttpErrors(async (req, res) => {
    const { platform } = await readJsonObject(req)
    assertPlatform(platform)

    const challenge = await peage.createChallenge(platform)
    res.json({ challenge })
  })
}

function solveHandler(peage: Peage): RequestHandler {
  return withHttpErrors(async (req, res) => {
    const body = await readJsonObject(req)
    assertValidSolveRequest(body)

    await peage.solveChallenge({
      challenge: body.challenge,
      keyId: body.keyId,
      platform: body.platform,
      proof: decodeBase64url(body.proof),
    })
    res.status(204).end()
  })
}

function protectMiddleware(peage: Peage, maxBodyBytes: number): RequestHandler {
  return withHttpErrors(async (req, res, next) => {
    assertBodyUnread(req)

    const verified = await peage.verifyAssertion({
      keyId: readRequiredHeader(req, HTTP_HEADER_KEY_ID),
      assertion: decodeBase64url(readRequiredHeader(req, HTTP_HEADER_ASSERTION)),
      method: req.method,
      path: originFormOf(req.originalUrl),
      readBody: () => readDecodedBodyBounded(req, maxBodyBytes),
    })

    res.locals.peage = verified
    if (verified.body.length > 0 && req.is(['json', '+json'])) {
      req.body = parseJson(verified.body)
    }
    next()
  })
}

/** Returns the request `protect` verified; throws when `protect` did not run before the handler. */
export function verifiedRequestOf(res: Response): VerifiedRequest {
  const verified = res.locals.peage
  assertVerifiedByProtect(verified)
  return verified
}

/**
 * Péage core plus the `challenge` and `solve` handlers and the `protect`
 * middleware. Mount `protect` before any body parser: it reads the body
 * itself. Body parsers mounted after it are skipped, so `req.body` stays
 * undefined unless the verified body is non-empty JSON (`application/json` or
 * `+json`), which `protect` parses into `req.body`. `verifiedRequestOf(res).body`
 * holds the verified body whatever its type.
 */
export function createPeage(config: PeageExpressConfig): PeageExpress {
  const maxBodyBytes = config.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES
  assertValidMaxBodyBytes(maxBodyBytes)
  const peage = createCorePeage(config)
  return {
    ...peage,
    challenge: challengeHandler(peage),
    solve: solveHandler(peage),
    protect: protectMiddleware(peage, maxBodyBytes),
  }
}
