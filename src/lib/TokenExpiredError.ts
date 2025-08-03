import { JsonWebTokenError } from './JsonWebTokenError.js';

export class TokenExpiredError extends JsonWebTokenError {
  override name: string = 'TokenExpiredError';
  expiredAt: Date;

  constructor(message: string, expiredAt: Date) {
    super(message);
    this.expiredAt = expiredAt;
  }
}