const jwt = require('../index');
const PS_SUPPORTED = require('../lib/psSupported');
const fs = require('fs');
const path = require('path');

const ms = require('ms');

function loadKey(filename) {
  return fs.readFileSync(path.join(__dirname, filename));
}

const algorithms = {
  // RSA algorithms
  RS256: {
    pub_key: loadKey('pub.pem'),
    priv_key: loadKey('priv.pem'),
    invalid_pub_key: loadKey('invalid_pub.pem')
  },
  RS384: {
    pub_key: loadKey('pub.pem'),
    priv_key: loadKey('priv.pem'),
    invalid_pub_key: loadKey('invalid_pub.pem')
  },
  RS512: {
    pub_key: loadKey('pub.pem'),
    priv_key: loadKey('priv.pem'),
    invalid_pub_key: loadKey('invalid_pub.pem')
  },
  // ECDSA algorithms
  ES256: {
    priv_key: loadKey('ecdsa-private.pem'),
    pub_key: loadKey('ecdsa-public.pem'),
    invalid_pub_key: loadKey('ecdsa-public-invalid.pem')
  },
  ES384: {
    priv_key: loadKey('secp384r1-private.pem'),
    pub_key: loadKey('secp384r1-public.pem'),
    invalid_pub_key: loadKey('ecdsa-public-invalid.pem')
  },
  ES512: {
    priv_key: loadKey('secp521r1-private.pem'),
    pub_key: loadKey('secp521r1-public.pem'),
    invalid_pub_key: loadKey('ecdsa-public-invalid.pem')
  },
  ES256K: {
    priv_key: loadKey('secp256k1-private.pem'),
    pub_key: loadKey('secp256k1-public.pem'),
    invalid_pub_key: loadKey('ecdsa-public-invalid.pem')
  },
  // EdDSA algorithms
  EdDSA: {
    priv_key: loadKey('ed25519-private.pem'),
    pub_key: loadKey('ed25519-public.pem'),
    invalid_pub_key: loadKey('ed448-public.pem')  // Different curve as invalid key
  }
};

if (PS_SUPPORTED) {
  // RSA-PSS algorithms
  algorithms.PS256 = {
    pub_key: loadKey('pub.pem'),
    priv_key: loadKey('priv.pem'),
    invalid_pub_key: loadKey('invalid_pub.pem')
  };
  algorithms.PS384 = {
    pub_key: loadKey('pub.pem'),
    priv_key: loadKey('priv.pem'),
    invalid_pub_key: loadKey('invalid_pub.pem')
  };
  algorithms.PS512 = {
    pub_key: loadKey('pub.pem'),
    priv_key: loadKey('priv.pem'),
    invalid_pub_key: loadKey('invalid_pub.pem')
  };
}


describe('Asymmetric Algorithms', () => {
  Object.keys(algorithms).forEach((algorithm) => {
    describe(algorithm, () => {
      let pub, priv, invalid_pub;

      beforeEach(() => {
        pub = algorithms[algorithm].pub_key;
        priv = algorithms[algorithm].priv_key;
        // "invalid" means it is not the public key for the loaded "priv" key
        invalid_pub = algorithms[algorithm].invalid_pub_key;
      });

      describe('when signing a token', () => {
        let token;

        beforeEach(() => {
          token = jwt.sign({ foo: 'bar' }, priv, { algorithm });
        });

        it('should be syntactically valid', () => {
          expect(typeof token).toBe('string');
          expect(token.split('.')).toHaveLength(3);
        });

        describe('asynchronous', () => {
          it('should validate with public key', (done) => {
            jwt.verify(token, pub, (err, decoded) => {
              expect(decoded.foo).toBeTruthy();
              expect(decoded.foo).toBe('bar');
              done();
            });
          });

          it('should throw with invalid public key', (done) => {
            jwt.verify(token, invalid_pub, (err, decoded) => {
              expect(decoded).toBeUndefined();
              expect(err).not.toBeNull();
              done();
            });
          });
        });

        describe('synchronous', () => {
          it('should validate with public key', () => {
            const decoded = jwt.verify(token, pub);
            expect(decoded.foo).toBeTruthy();
            expect(decoded.foo).toBe('bar');
          });

          it('should throw with invalid public key', () => {
            const jwtVerify = jwt.verify.bind(null, token, invalid_pub)
            expect(jwtVerify).toThrow('invalid signature');
          });
        });

      });

      describe('when signing a token with expiration', () => {
        it('should be valid expiration', (done) => {
          const token = jwt.sign({ foo: 'bar' }, priv, { algorithm, expiresIn: '10m' });
          jwt.verify(token, pub, (err, decoded) => {
            expect(decoded).not.toBeNull();
            expect(err).toBeNull();
            done();
          });
        });

        it('should be invalid', (done) => {
          // expired token
          const token = jwt.sign({ foo: 'bar' }, priv, { algorithm, expiresIn: -1 * ms('10m') });
          jwt.verify(token, pub, (err, decoded) => {
            expect(decoded).toBeUndefined();
            expect(err).not.toBeNull();
            expect(err.name).toBe('TokenExpiredError');
            expect(err.expiredAt).toBeInstanceOf(Date);
            expect(err).toBeInstanceOf(jwt.TokenExpiredError);
            done();
          });
        });

        it('should NOT be invalid', (done) => {
          // expired token
          const token = jwt.sign({ foo: 'bar' }, priv, { algorithm, expiresIn: -1 * ms('10m') });

          jwt.verify(token, pub, { ignoreExpiration: true }, (err, decoded) => {
            expect(decoded.foo).toBeTruthy();
            expect(decoded.foo).toBe('bar');
            done();
          });
        });
      });

      describe('when verifying a malformed token', () => {
        it('should throw', (done) => {
          jwt.verify('fruit.fruit.fruit', pub, (err, decoded) => {
            expect(decoded).toBeUndefined();
            expect(err).not.toBeNull();
            expect(err.name).toBe('JsonWebTokenError');
            done();
          });
        });
      });

      describe('when decoding a jwt token with additional parts', () => {
        let token;

        beforeEach(() => {
          token = jwt.sign({ foo: 'bar' }, priv, { algorithm });
        });

        it('should throw', (done) => {
          jwt.verify(`${token  }.foo`, pub, (err, decoded) => {
            expect(decoded).toBeUndefined();
            expect(err).not.toBeNull();
            done();
          });
        });
      });

      describe('when decoding a invalid jwt token', () => {
        it('should return null', (done) => {
          const payload = jwt.decode('whatever.token');
          expect(payload).toBeNull();
          done();
        });
      });

      describe('when decoding a valid jwt token', () => {
        it('should return the payload', (done) => {
          const obj = { foo: 'bar' };
          const token = jwt.sign(obj, priv, { algorithm });
          const payload = jwt.decode(token);
          expect(payload.foo).toBe(obj.foo);
          done();
        });
        it('should return the header and payload and signature if complete option is set', (done) => {
          const obj = { foo: 'bar' };
          const token = jwt.sign(obj, priv, { algorithm });
          const decoded = jwt.decode(token, { complete: true });
          expect(decoded.payload.foo).toBe(obj.foo);
          expect(decoded.header).toEqual({ typ: 'JWT', alg: algorithm });
          expect(typeof decoded.signature == 'string').toBeTruthy();
          done();
        });
      });
    });
  });

  describe('when signing a token with an unsupported private key type', () => {
    it('should throw an error', () => {
      const obj = { foo: 'bar' };
      const key = loadKey('dsa-private.pem');
      const algorithm = 'RS256';

      expect(() => {
        jwt.sign(obj, key, { algorithm });
      }).to.throw('Unknown key type "dsa".');
    });
  });

  describe('when signing a token with an incorrect private key type', () => {
    it('should throw a validation error if key validation is enabled', () => {
      const obj = { foo: 'bar' };
      const key = loadKey('rsa-private.pem');
      const algorithm = 'ES256';

      expect(() => {
        jwt.sign(obj, key, { algorithm });
      }).to.throw(/"alg" parameter for "rsa" key type must be one of:/);
    });

    it('should throw an unknown error if key validation is disabled', () => {
      const obj = { foo: 'bar' };
      const key = loadKey('rsa-private.pem');
      const algorithm = 'ES256';

      expect(() => {
        jwt.sign(obj, key, { algorithm, allowInvalidAsymmetricKeyTypes: true });
      }).not.throw(/"alg" parameter for "rsa" key type must be one of:/);
    });
  });
});
