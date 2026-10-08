// The one error type that reaches clients: status, a machine-readable code, a message,
// and optional extra fields (retryAfter, findings, retryable) merged into the error body.
export class GatewayError extends Error {
  constructor(status, code, message, extra = {}) {
    super(message);
    this.status = status;
    this.code = code;
    this.extra = extra;
  }
}
