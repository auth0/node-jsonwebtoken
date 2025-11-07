const assert = require('assert');
const jwt = require('../index.js');

describe('Fix: jwt.sign callback should not be called twice', function () {
  it('should call callback only once when payload.iss conflicts with options.issuer', function (done) {
    let callbackCount = 0;

    jwt.sign(
      { iss: 'bar', iat: 1757476476 },
      'secret',
      { algorithm: 'HS256', issuer: 'foo' },
      (err) => {
        callbackCount++;
        assert.ok(err, 'Expected an error due to issuer conflict');
        assert.strictEqual(
          err.message,
          'Bad "options.issuer" option. The payload already has an "iss" property.'
        );
        assert.strictEqual(callbackCount, 1, 'Callback was called more than once');
        done();
      }
    );
  });
});
