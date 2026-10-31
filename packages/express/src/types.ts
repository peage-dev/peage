import type { Peage, PeageConfig } from '@peage/core'
import type { RequestHandler, Router } from 'express'

/** Options for `createPeage`: Péage core's config plus the body size limit. */
export type PeageExpressConfig = PeageConfig & {
  /**
   * Largest body `protect` buffers, both as received and once its content
   * coding is removed; a larger one gets 413. Defaults to 1 MiB.
   * Past three times this size, the 413 carries `Connection: close` and the
   * connection is closed.
   */
  maxBodyBytes?: number
}

/** Returned by `createPeage`: Péage core plus Express handlers for its routes. */
export type PeageExpress = Peage & {
  /** Handles the challenge request (`CHALLENGE_PATH` by default): `{ platform }` → `{ challenge }`. */
  challenge: RequestHandler
  /** Handles the solve request (`SOLVE_PATH` by default): registers the attested key, answers 204. */
  solve: RequestHandler
  /**
   * Serves `challenge` at `POST CHALLENGE_PATH` and `solve` at `POST SOLVE_PATH`;
   * mount it under a prefix with `app.use('/v1', peage.router)`.
   */
  router: Router
  /**
   * Sets `res.locals.peage` to the `VerifiedRequest`, which `verifiedRequestOf(res)` returns.
   * With `debugToken` configured, a request carrying a non-empty `X-Peage-Debug-Token`
   * header needs no `X-Peage-KeyId` or `X-Peage-Assertion` header.
   */
  protect: RequestHandler
}
