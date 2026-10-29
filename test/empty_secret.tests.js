'use strict';

const jwt = require('../index');
const JsonWebTokenError = require('../lib/JsonWebTokenError');
const expect = require('chai').expect;
const crypto = require('crypto');

// Some older Node.js versions reject zero-length keys in createSecretKey(), in
// which case the key is reported as invalid key material instead. Either way
// the empty key must be rejected.
const SIGN_ERROR = /secretOrPrivateKey must have a value|secretOrPrivateKey is not valid key material/;
const VERIFY_ERROR = /secret or public key must be provided|secretOrPublicKey is not valid key material/;

function createEmptySecretKey() {
  try {
    return crypto.createSecretKey(Buffer.alloc(0));
  } catch (_) {
    return undefined;
  }
}

const emptySecretKey = createEmptySecretKey();
const itWithEmptyKeyObject = emptySecretKey ? it : it.skip;

function base64url(value) {
  return Buffer.from(value).toString('base64').replace(/[=]/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

// HS256 token signed with a zero-length key, built without jsonwebtoken.
function signWithEmptyKey(payload) {
  const signingInput = base64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' })) + '.' + base64url(JSON.stringify(payload));
  const signature = crypto.createHmac('sha256', Buffer.alloc(0)).update(signingInput).digest();
  return signingInput + '.' + base64url(signature);
}

describe('empty HMAC secret', function () {
  describe('when signing', function () {
    it('should reject an empty string', function () {
      expect(function () {
        jwt.sign({ foo: 'bar' }, '', { algorithm: 'HS256' });
      }).to.throw(Error, 'secretOrPrivateKey must have a value');
    });

    it('should reject an empty Buffer', function () {
      expect(function () {
        jwt.sign({ foo: 'bar' }, Buffer.alloc(0), { algorithm: 'HS256' });
      }).to.throw(Error, SIGN_ERROR);
    });

    it('should reject an empty Buffer with the default algorithm', function () {
      expect(function () {
        jwt.sign({ foo: 'bar' }, Buffer.alloc(0));
      }).to.throw(Error, SIGN_ERROR);
    });

    itWithEmptyKeyObject('should reject an empty secret KeyObject', function () {
      expect(function () {
        jwt.sign({ foo: 'bar' }, emptySecretKey, { algorithm: 'HS256' });
      }).to.throw(Error, 'secretOrPrivateKey must have a value');
    });

    it('should return an error to the callback for an empty Buffer', function (done) {
      jwt.sign({ foo: 'bar' }, Buffer.alloc(0), { algorithm: 'HS256' }, function (err, token) {
        expect(token).to.be.undefined;
        expect(err).to.be.instanceOf(Error);
        expect(err.message).to.match(SIGN_ERROR);
        done();
      });
    });

    it('should still sign with an empty Buffer when the algorithm is none', function () {
      const token = jwt.sign({ foo: 'bar' }, Buffer.alloc(0), { algorithm: 'none' });
      expect(token.split('.')[2]).to.equal('');
    });
  });

  describe('when verifying', function () {
    const token = signWithEmptyKey({ foo: 'bar' });

    it('should reject an empty string', function () {
      expect(function () {
        jwt.verify(token, '');
      }).to.throw(JsonWebTokenError, 'secret or public key must be provided');
    });

    it('should reject an empty Buffer', function () {
      expect(function () {
        jwt.verify(token, Buffer.alloc(0));
      }).to.throw(JsonWebTokenError, VERIFY_ERROR);
    });

    it('should reject an empty Buffer when HS256 is explicitly allowed', function () {
      expect(function () {
        jwt.verify(token, Buffer.alloc(0), { algorithms: ['HS256'] });
      }).to.throw(JsonWebTokenError, VERIFY_ERROR);
    });

    itWithEmptyKeyObject('should reject an empty secret KeyObject', function () {
      expect(function () {
        jwt.verify(token, emptySecretKey, { algorithms: ['HS256'] });
      }).to.throw(JsonWebTokenError, 'secret or public key must be provided');
    });

    it('should reject an empty Buffer returned by a secret callback', function (done) {
      const getSecret = function (header, callback) {
        callback(null, Buffer.alloc(0));
      };
      jwt.verify(token, getSecret, { algorithms: ['HS256'] }, function (err, decoded) {
        expect(decoded).to.be.undefined;
        expect(err).to.be.instanceOf(JsonWebTokenError);
        expect(err.message).to.match(VERIFY_ERROR);
        done();
      });
    });

    it('should still verify a token signed with a non-empty Buffer secret', function () {
      const secret = Buffer.from('a-non-empty-secret');
      const decoded = jwt.verify(jwt.sign({ foo: 'bar' }, secret), secret);
      expect(decoded.foo).to.equal('bar');
    });
  });
});
