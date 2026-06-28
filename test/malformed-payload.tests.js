const jwt = require('../index');
const crypto = require('crypto');
const expect = require('chai').expect;
const assert = require('chai').assert;
const JsonWebTokenError = require('../lib/JsonWebTokenError');

/**
 * Helper to create a properly signed HS256 token with a given raw payload
 * (bypasses JSON serialization so we can inject non-JSON payloads).
 */
function createTokenWithRawPayload(rawPayload, secret) {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(rawPayload).toString('base64url');
  const sigInput = header + '.' + payload;
  const sig = crypto.createHmac('sha256', secret).update(sigInput).digest('base64url');
  return sigInput + '.' + sig;
}

describe('malformed JSON payload', function () {
  const secret = 'shhhh';

  describe('synchronous (no callback)', function () {
    it('should throw JsonWebTokenError with "jwt malformed" for non-JSON payload', function () {
      const token = createTokenWithRawPayload('not-json', secret);

      expect(function () {
        jwt.verify(token, secret);
      }).to.throw(JsonWebTokenError, 'jwt malformed');
    });

    it('should NOT throw SyntaxError for non-JSON payload', function () {
      const token = createTokenWithRawPayload('not-json', secret);

      expect(function () {
        jwt.verify(token, secret);
      }).to.not.throw(SyntaxError);
    });
  });

  describe('callback mode', function () {
    it('should return JsonWebTokenError with "jwt malformed" for non-JSON payload', function (done) {
      const token = createTokenWithRawPayload('not-json', secret);

      jwt.verify(token, secret, function (err) {
        assert.isNotNull(err);
        assert.equal(err.name, 'JsonWebTokenError');
        assert.equal(err.message, 'jwt malformed');
        done();
      });
    });

    it('should return JsonWebTokenError for payload with invalid UTF-8 JSON', function (done) {
      const token = createTokenWithRawPayload('{invalid json', secret);

      jwt.verify(token, secret, function (err) {
        assert.isNotNull(err);
        assert.equal(err.name, 'JsonWebTokenError');
        assert.equal(err.message, 'jwt malformed');
        done();
      });
    });
  });

  describe('valid tokens still work', function () {
    it('should verify a token with a valid JSON object payload', function (done) {
      const token = jwt.sign({ foo: 'bar' }, secret);

      jwt.verify(token, secret, function (err, decoded) {
        assert.isNull(err);
        assert.equal(decoded.foo, 'bar');
        done();
      });
    });

    it('should verify a token with a string payload', function () {
      const token = jwt.sign('hello', secret);
      const result = jwt.verify(token, secret);
      assert.equal(result, 'hello');
    });
  });
});
