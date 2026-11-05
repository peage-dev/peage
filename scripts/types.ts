export type ServiceAccount = { client_email: string; private_key: string; token_uri: string }

/** The fields of `npm stage list --json` the release script reads. */
export type StagedVersion = { id: string; packageName: string; version: string }
