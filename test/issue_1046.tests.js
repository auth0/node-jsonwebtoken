const jwt = require('../index');
const crypto = require('crypto');
const assert = require('chai').assert;
const expect = require('chai').expect;
const JsonWebTokenError = require('../lib/JsonWebTokenError');

describe('issue 1046', function () {
  it('verifies HS256 tokens signed with a string secret', function () {
    const secret = 'a-shared-secret-of-reasonable-length';
    const token = jwt.sign({ sub: 'u' }, secret, { algorithm: 'HS256' });
    const decoded = jwt.verify(token, secret, { algorithms: ['HS256'] });
    assert.equal(decoded.sub, 'u');
  });

  it('still rejects HMAC verification with a PEM public key', function () {
    const { publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const pem = publicKey.export({ type: 'spki', format: 'pem' });
    const maliciousToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InJzYUtleUlkIn0.eyJmb28iOiJiYXIiLCJpYXQiOjE2NTk1MTA2MDh9.cOcHI1TXPbxTMlyVTfjArSWskrmezbrG8iR7uJHwtrQ';

    expect(() => jwt.verify(maliciousToken, pem, { algorithms: ['RS256', 'HS256'] }))
      .to.throw(JsonWebTokenError, 'must be a symmetric key');
  });

  it('rejects an HS256 token when the PEM public key has text before the header', function () {
    const { publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const key = 'public key for service X\n' + publicKey.export({ type: 'spki', format: 'pem' });
    const b64u = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
    const data = `${b64u({ alg: 'HS256', typ: 'JWT' })}.${b64u({ sub: 'attacker' })}`;
    const token = `${data}.${crypto.createHmac('sha256', key).update(data).digest('base64url')}`;

    expect(() => jwt.verify(token, key)).to.throw(JsonWebTokenError, 'invalid algorithm');
  });

  it('verifies a string secret the same as its KeyObject', function () {
    const secret = 'a-shared-secret-of-reasonable-length';
    const token = jwt.sign({ sub: 'u' }, secret, { algorithm: 'HS256' });
    const keyObject = crypto.createSecretKey(Buffer.from(secret));
    const fromString = jwt.verify(token, secret);
    const fromKey = jwt.verify(token, keyObject);
    assert.deepEqual(fromString, fromKey);
  });

  it('still rejects a wrong string secret', function () {
    const token = jwt.sign({ sub: 'u' }, 'correct-secret-value', { algorithm: 'HS256' });
    expect(() => jwt.verify(token, 'wrong-secret-value')).to.throw();
  });
});
