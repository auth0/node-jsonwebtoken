const jwt = require('../index');
const crypto = require("crypto");
const {expect} = require('chai');
const JsonWebTokenError = require("../lib/JsonWebTokenError");

describe('when verifying a malicious token', function () {
  // attacker has access to the public rsa key, but crafts the token as HS256
  // with kid set to the id of the rsa key, instead of the id of the hmac secret.
  // const maliciousToken = jwt.sign(
  //   {foo: 'bar'},
  //   pubRsaKey,
  //   {algorithm: 'HS256', keyid: 'rsaKeyId'}
  // );
  // consumer accepts self signed tokens (HS256) and third party tokens (RS256)
  const options = {algorithms: ['RS256', 'HS256']};

  const {
    publicKey: pubRsaKey
  } = crypto.generateKeyPairSync('rsa', {modulusLength: 2048});

  it('should not allow HMAC verification with an RSA key in KeyObject format', function () {
    const maliciousToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InJzYUtleUlkIn0.eyJmb28iOiJiYXIiLCJpYXQiOjE2NTk1MTA2MDh9.cOcHI1TXPbxTMlyVTfjArSWskrmezbrG8iR7uJHwtrQ';

    expect(() => jwt.verify(maliciousToken, pubRsaKey, options)).to.throw(JsonWebTokenError, 'must be of type secret when using HS');
  })

  it('should not allow HMAC verification with an RSA key in PEM format', function () {
    const maliciousToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InJzYUtleUlkIn0.eyJmb28iOiJiYXIiLCJpYXQiOjE2NTk1MTA2MDh9.cOcHI1TXPbxTMlyVTfjArSWskrmezbrG8iR7uJHwtrQ';

    expect(() => jwt.verify(maliciousToken, pubRsaKey.export({type: 'spki', format: 'pem'}), options)).to.throw(JsonWebTokenError, 'must be a symmetric key');
  })
})
