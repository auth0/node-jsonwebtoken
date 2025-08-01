'use strict';

const jwt = require('../');
const util = require('util');
const testUtils = require('./test-utils');

function signWithIssuer(issuer, payload, callback) {
  const options = {algorithm: 'HS256'};
  if (issuer !== undefined) {
    options.issuer = issuer;
  }
  testUtils.signJWTHelper(payload, 'secret', options, callback);
}

describe('issuer', () => {
  describe('`jwt.sign` "issuer" option validation', () => {
    [
      true,
      false,
      null,
      -1,
      0,
      1,
      -1.1,
      1.1,
      -Infinity,
      Infinity,
      NaN,
      [],
      ['foo'],
      {},
      {foo: 'bar'},
    ].forEach((issuer) => {
      it(`should error with with value ${util.inspect(issuer)}`, (done) => {
        signWithIssuer(issuer, {}, (err) => {
          testUtils.asyncCheck(done, () => {
            expect(err).toBeInstanceOf(Error);
            expect(err).toHaveProperty('message', '"issuer" must be a string');
          });
        });
      });
    });

    // undefined needs special treatment because {} is not the same as {issuer: undefined}
    it('should error with with value undefined', (done) => {
      testUtils.signJWTHelper({}, 'secret', {issuer: undefined, algorithm: 'HS256'}, (err) => {
        testUtils.asyncCheck(done, () => {
          expect(err).toBeInstanceOf(Error);
          expect(err).toHaveProperty('message', '"issuer" must be a string');
        });
      });
    });

    it('should error when "iss" is in payload', (done) => {
      signWithIssuer('foo', {iss: 'bar'}, (err) => {
        testUtils.asyncCheck(done, () => {
          expect(err).toBeInstanceOf(Error);
          expect(err).toHaveProperty(
            'message',
            'Bad "options.issuer" option. The payload already has an "iss" property.'
          );
        });
      });
    });

    it('should error with a string payload', (done) => {
      signWithIssuer('foo', 'a string payload', (err) => {
        testUtils.asyncCheck(done, () => {
          expect(err).toBeInstanceOf(Error);
          expect(err).toHaveProperty(
            'message',
            'invalid issuer option for string payload'
          );
        });
      });
    });

    it('should error with a Buffer payload', (done) => {
      signWithIssuer('foo', new Buffer('a Buffer payload'), (err) => {
        testUtils.asyncCheck(done, () => {
          expect(err).toBeInstanceOf(Error);
          expect(err).toHaveProperty(
            'message',
            'invalid issuer option for object payload'
          );
        });
      });
    });
  });

  describe('when signing and verifying a token', () => {
    it('should not verify "iss" if verify "issuer" option not provided', (done) => {
      signWithIssuer(undefined, {iss: 'foo'}, (e1, token) => {
        testUtils.verifyJWTHelper(token, 'secret', {}, (e2, decoded) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).toBeNull();
            expect(e2).toBeNull();
            expect(decoded).toHaveProperty('iss', 'foo');
          });
        })
      });
    });

    describe('with string "issuer" option', () => {
      it('should verify with a string "issuer"', (done) => {
        signWithIssuer('foo', {}, (e1, token) => {
          testUtils.verifyJWTHelper(token, 'secret', {issuer: 'foo'}, (e2, decoded) => {
            testUtils.asyncCheck(done, () => {
              expect(e1).toBeNull();
              expect(e2).toBeNull();
              expect(decoded).toHaveProperty('iss', 'foo');
            });
          })
        });
      });

      it('should verify with a string "iss"', (done) => {
        signWithIssuer(undefined, {iss: 'foo'}, (e1, token) => {
          testUtils.verifyJWTHelper(token, 'secret', {issuer: 'foo'}, (e2, decoded) => {
            testUtils.asyncCheck(done, () => {
              expect(e1).toBeNull();
              expect(e2).toBeNull();
              expect(decoded).toHaveProperty('iss', 'foo');
            });
          })
        });
      });

      it('should error if "iss" does not match verify "issuer" option', (done) => {
        signWithIssuer(undefined, {iss: 'foobar'}, (e1, token) => {
          testUtils.verifyJWTHelper(token, 'secret', {issuer: 'foo'}, (e2) => {
            testUtils.asyncCheck(done, () => {
              expect(e1).toBeNull();
              expect(e2).toBeInstanceOf(jwt.JsonWebTokenError);
              expect(e2).toHaveProperty('message', 'jwt issuer invalid. expected: foo');
            });
          })
        });
      });

      it('should error without "iss" and with verify "issuer" option', (done) => {
        signWithIssuer(undefined, {}, (e1, token) => {
          testUtils.verifyJWTHelper(token, 'secret', {issuer: 'foo'}, (e2) => {
            testUtils.asyncCheck(done, () => {
              expect(e1).toBeNull();
              expect(e2).toBeInstanceOf(jwt.JsonWebTokenError);
              expect(e2).toHaveProperty('message', 'jwt issuer invalid. expected: foo');
            });
          })
        });
      });
    });

    describe('with array "issuer" option', () => {
      it('should verify with a string "issuer"', (done) => {
        signWithIssuer('bar', {}, (e1, token) => {
          testUtils.verifyJWTHelper(token, 'secret', {issuer: ['foo', 'bar']}, (e2, decoded) => {
            testUtils.asyncCheck(done, () => {
              expect(e1).toBeNull();
              expect(e2).toBeNull();
              expect(decoded).toHaveProperty('iss', 'bar');
            });
          })
        });
      });

      it('should verify with a string "iss"', (done) => {
        signWithIssuer(undefined, {iss: 'foo'}, (e1, token) => {
          testUtils.verifyJWTHelper(token, 'secret', {issuer: ['foo', 'bar']}, (e2, decoded) => {
            testUtils.asyncCheck(done, () => {
              expect(e1).toBeNull();
              expect(e2).toBeNull();
              expect(decoded).toHaveProperty('iss', 'foo');
            });
          })
        });
      });

      it('should error if "iss" does not match verify "issuer" option', (done) => {
        signWithIssuer(undefined, {iss: 'foobar'}, (e1, token) => {
          testUtils.verifyJWTHelper(token, 'secret', {issuer: ['foo', 'bar']}, (e2) => {
            testUtils.asyncCheck(done, () => {
              expect(e1).toBeNull();
              expect(e2).toBeInstanceOf(jwt.JsonWebTokenError);
              expect(e2).toHaveProperty('message', 'jwt issuer invalid. expected: foo,bar');
            });
          })
        });
      });

      it('should error without "iss" and with verify "issuer" option', (done) => {
        signWithIssuer(undefined, {}, (e1, token) => {
          testUtils.verifyJWTHelper(token, 'secret', {issuer: ['foo', 'bar']}, (e2) => {
            testUtils.asyncCheck(done, () => {
              expect(e1).toBeNull();
              expect(e2).toBeInstanceOf(jwt.JsonWebTokenError);
              expect(e2).toHaveProperty('message', 'jwt issuer invalid. expected: foo,bar');
            });
          })
        });
      });
    });
  });
});
