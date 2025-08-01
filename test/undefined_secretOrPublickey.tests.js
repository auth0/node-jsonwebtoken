const jwt = require('../index');
const JsonWebTokenError = require('../lib/JsonWebTokenError');

const TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M';

describe('verifying without specified secret or public key', () => {
  it('should not verify null', () => {
    expect(() => {
      jwt.verify(TOKEN, null);
    }).to.throw(JsonWebTokenError, /secret or public key must be provided/);
  });

  it('should not verify undefined', () => {
    expect(() => {
      jwt.verify(TOKEN);
    }).to.throw(JsonWebTokenError, /secret or public key must be provided/);
  });
});