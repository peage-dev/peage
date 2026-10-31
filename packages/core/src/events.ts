import { isPlatform } from '@peage/protocol'

import type { PeageError } from './errors.ts'
import type { PeageEvent, RegistrationRequest, SignedRequest, VerifiedRequest } from './types.ts'

import { isCanonicalKeyId } from './guards.ts'

type RegistrationRejectedEvent = Extract<PeageEvent, { type: 'registration.rejected' }>
type RequestRejectedEvent = Extract<PeageEvent, { type: 'request.rejected' }>
type RequestVerifiedEvent = Extract<PeageEvent, { type: 'request.verified' }>

export function registrationRejectedEvent(
  request: RegistrationRequest,
  error: PeageError,
): RegistrationRejectedEvent {
  const event: RegistrationRejectedEvent = { type: 'registration.rejected', error }
  if (isCanonicalKeyId(request.keyId)) {
    event.keyId = request.keyId
  }
  if (isPlatform(request.platform)) {
    event.platform = request.platform
  }
  return event
}

export function requestRejectedEvent(
  request: SignedRequest,
  error: PeageError,
): RequestRejectedEvent {
  const event: RequestRejectedEvent = { type: 'request.rejected', error }
  if (isCanonicalKeyId(request.keyId)) {
    event.keyId = request.keyId
  }
  return event
}

export function requestVerifiedEvent(verified: VerifiedRequest): RequestVerifiedEvent {
  if (verified.debug) {
    return { type: 'request.verified', debug: true }
  }
  return {
    type: 'request.verified',
    debug: false,
    keyId: verified.keyId,
    platform: verified.platform,
  }
}
