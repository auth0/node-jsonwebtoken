/**
 * Base error for all JWT-related errors
 */
export class JsonWebTokenError extends Error {
  constructor(message: string, error?: Error);
  inner: Error;
}

/**
 * Error thrown when a token has expired
 */
export class TokenExpiredError extends JsonWebTokenError {
  constructor(message: string, expiredAt: Date);
  expiredAt: Date;
}

/**
 * Error thrown when a token is used before its 'nbf' claim
 */
export class NotBeforeError extends JsonWebTokenError {
  constructor(message: string, date: Date);
  date: Date;
}

/**
 * Union type of all possible verification errors
 */
export type VerifyErrors =
  | TokenExpiredError
  | JsonWebTokenError
  | NotBeforeError;