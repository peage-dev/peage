import { execFileSync } from 'node:child_process'
import { sign } from 'node:crypto'
import { readFile } from 'node:fs/promises'

import type { ServiceAccount } from './types.ts'

import {
  assertUploadKeystoreConfigured,
  assertValidAccessTokenResponse,
  assertValidBundle,
  assertValidBundleListing,
  assertValidEdit,
  assertValidServiceAccount,
} from './asserters.ts'

const PACKAGE_NAME = 'dev.peage.rnexample'
const TRACK = 'internal'
const SCOPE = 'https://www.googleapis.com/auth/androidpublisher'
const API = `https://androidpublisher.googleapis.com/androidpublisher/v3/applications/${PACKAGE_NAME}`
const UPLOAD_API = `https://androidpublisher.googleapis.com/upload/androidpublisher/v3/applications/${PACKAGE_NAME}`
const ANDROID_DIRECTORY = new URL('../examples/RNExample/android/', import.meta.url)
const BUNDLE = new URL('app/build/outputs/bundle/release/app-release.aab', ANDROID_DIRECTORY)
const SERVICE_ACCOUNT_VARIABLE = 'PEAGE_PLAY_SERVICE_ACCOUNT'
const UPLOAD_KEYSTORE_VARIABLES = [
  'ORG_GRADLE_PROJECT_PEAGE_UPLOAD_STORE_FILE',
  'ORG_GRADLE_PROJECT_PEAGE_UPLOAD_STORE_PASSWORD',
  'ORG_GRADLE_PROJECT_PEAGE_UPLOAD_KEY_ALIAS',
  'ORG_GRADLE_PROJECT_PEAGE_UPLOAD_KEY_PASSWORD',
]
const TOKEN_LIFETIME_SECONDS = 3600

/** JSON.parse errors quote the input, which here is a private key. */
function readServiceAccount(): ServiceAccount {
  const json = process.env[SERVICE_ACCOUNT_VARIABLE]
  if (!json) {
    throw new Error(`Set ${SERVICE_ACCOUNT_VARIABLE} to the service account JSON key`)
  }
  let account: unknown
  try {
    account = JSON.parse(json)
  } catch {
    throw new Error(`${SERVICE_ACCOUNT_VARIABLE} is not valid JSON`)
  }
  assertValidServiceAccount(account, SERVICE_ACCOUNT_VARIABLE)
  return account
}

function versionCodeOf(bundle: unknown): number {
  assertValidBundle(bundle)
  return bundle.versionCode
}

function base64url(value: string | Uint8Array): string {
  return Buffer.from(value).toString('base64url')
}

/** A JWT the service account signs to ask Google for an access token. */
function signedAssertion(account: ServiceAccount): string {
  const issuedAt = Math.floor(Date.now() / 1000)
  const header = base64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }))
  const claims = base64url(
    JSON.stringify({
      iss: account.client_email,
      scope: SCOPE,
      aud: account.token_uri,
      iat: issuedAt,
      exp: issuedAt + TOKEN_LIFETIME_SECONDS,
    }),
  )
  const signature = sign('RSA-SHA256', Buffer.from(`${header}.${claims}`), account.private_key)
  return `${header}.${claims}.${base64url(signature)}`
}

async function readResponse(response: Response, operation: string): Promise<unknown> {
  const text = await response.text()
  if (!response.ok) {
    throw new Error(`${operation} failed (${response.status}): ${text}`)
  }
  return text ? JSON.parse(text) : undefined
}

async function fetchAccessToken(account: ServiceAccount): Promise<string> {
  const response = await fetch(account.token_uri, {
    method: 'POST',
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: signedAssertion(account),
    }),
  })
  const body = await readResponse(response, 'Access token request')
  assertValidAccessTokenResponse(body)
  return body.access_token
}

/** Play changes go through an "edit": opened, changed, then committed or deleted. */
function createPlayApi(accessToken: string) {
  async function request(
    operation: string,
    url: string,
    init: { method: string; body?: string | Uint8Array; contentType?: string },
  ): Promise<unknown> {
    const headers: Record<string, string> = { authorization: `Bearer ${accessToken}` }
    if (init.contentType) {
      headers['content-type'] = init.contentType
    }
    const response = await fetch(url, { method: init.method, headers, body: init.body })
    return readResponse(response, operation)
  }

  async function openEdit(): Promise<string> {
    const edit = await request('Opening an edit', `${API}/edits`, { method: 'POST' })
    assertValidEdit(edit)
    return edit.id
  }

  async function deleteEdit(editId: string): Promise<void> {
    await request('Deleting the edit', `${API}/edits/${editId}`, { method: 'DELETE' })
  }

  async function highestVersionCode(): Promise<number> {
    const editId = await openEdit()
    try {
      const listing = await request('Listing bundles', `${API}/edits/${editId}/bundles`, {
        method: 'GET',
      })
      assertValidBundleListing(listing)
      // Play omits `bundles` when nothing has been uploaded yet.
      const bundles: unknown[] = Array.isArray(listing.bundles) ? listing.bundles : []
      return Math.max(0, ...bundles.map(versionCodeOf))
    } finally {
      await deleteEdit(editId)
    }
  }

  async function uploadBundle(editId: string, bundle: Uint8Array): Promise<number> {
    const uploaded = await request(
      'Uploading the bundle',
      `${UPLOAD_API}/edits/${editId}/bundles?uploadType=media`,
      { method: 'POST', body: bundle, contentType: 'application/octet-stream' },
    )
    return versionCodeOf(uploaded)
  }

  async function assignToTrack(editId: string, versionCode: number): Promise<void> {
    const release = { versionCodes: [String(versionCode)], status: 'completed' }
    await request(`Assigning the ${TRACK} track`, `${API}/edits/${editId}/tracks/${TRACK}`, {
      method: 'PUT',
      body: JSON.stringify({ track: TRACK, releases: [release] }),
      contentType: 'application/json',
    })
  }

  async function commitEdit(editId: string): Promise<void> {
    await request('Committing the edit', `${API}/edits/${editId}:commit`, { method: 'POST' })
  }

  async function publishToTrack(bundle: Uint8Array): Promise<number> {
    const editId = await openEdit()
    try {
      const versionCode = await uploadBundle(editId, bundle)
      await assignToTrack(editId, versionCode)
      await commitEdit(editId)
      return versionCode
    } catch (error) {
      await deleteEdit(editId).catch(() => undefined)
      throw error
    }
  }

  return { highestVersionCode, publishToTrack }
}

function buildBundle(versionCode: number): void {
  const environment = { ...process.env }
  delete environment[SERVICE_ACCOUNT_VARIABLE]
  execFileSync('./gradlew', [':app:bundleRelease', `-PPEAGE_VERSION_CODE=${versionCode}`], {
    cwd: ANDROID_DIRECTORY,
    env: environment,
    stdio: 'inherit',
  })
}

async function main(): Promise<void> {
  assertUploadKeystoreConfigured(UPLOAD_KEYSTORE_VARIABLES)
  const play = createPlayApi(await fetchAccessToken(readServiceAccount()))

  const versionCode = (await play.highestVersionCode()) + 1
  console.log(`Building ${PACKAGE_NAME} versionCode ${versionCode}…`)
  buildBundle(versionCode)

  console.log('Uploading…')
  const publishedVersionCode = await play.publishToTrack(await readFile(BUNDLE))
  console.log(`versionCode ${publishedVersionCode} is rolling out to ${TRACK} testers.`)
}

await main()
