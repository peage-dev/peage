export class HttpStatusError extends Error {
  readonly status: number

  constructor(status: number) {
    super(`HTTP ${status}`)
    this.name = 'HttpStatusError'
    this.status = status
  }
}
