import { JsonWebTokenError } from './JsonWebTokenError.js';

export class NotBeforeError extends JsonWebTokenError {
  override name: string = 'NotBeforeError';
  date: Date;

  constructor(message: string, date: Date) {
    super(message);
    this.date = date;
  }
}