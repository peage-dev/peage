# Security policy

## Reporting a vulnerability

Use GitHub's
[private vulnerability reporting](https://github.com/peage-dev/peage/security/advisories/new),
not a public issue. Include the affected package and version, and steps to
reproduce.

I'll reply within 7 days if needed. Fixes may ship with a GitHub security
advisory that credits the reporter.

## Supported versions

Until 0.1, only the latest commit on `main`. After that, the latest release.

## Scope

In scope: anything that gets a request or a registration accepted without a
genuine device, or that leaks a device's key.

Out of scope:

- Replaying a signed request within its ~90-second validity window.
- Misconfiguration, such as accepting development attestations in
  production.
- Issues in Apple's or Google's attestation services.
