export class JsonWebTokenError extends Error {
  name: string = 'JsonWebTokenError';

  constructor(message: string, error?: Error) {
    super(message);
    if (error) {
      this.cause = error;
    }
    Error.captureStackTrace(this, this.constructor);
  }
}