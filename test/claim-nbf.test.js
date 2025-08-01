'use strict';

const jwt = require('../');
const util = require('util');
const testUtils = require('./test-utils');
const jws = require('jws');

function signWithNotBefore(notBefore, payload, callback) {
  const options = {algorithm: 'HS256'};
  if (notBefore !== undefined) {
    options.notBefore = notBefore;
  }
  testUtils.signJWTHelper(payload, 'secret', options, callback);
}

describe('not before', () => {
  describe('`jwt.sign` "notBefore" option validation', () => {
    [
      true,
      false,
      null,
      -1.1,
      1.1,
      -Infinity,
      Infinity,
      NaN,
      '',
      ' ',
      'invalid',
      [],
      ['foo'],
      {},
      {foo: 'bar'},
    ].forEach((notBefore) => {
      it(`should error with with value ${util.inspect(notBefore)}`, (done) => {
        signWithNotBefore(notBefore, {}, (err) => {
          testUtils.asyncCheck(done, () => {
            expect(err).toBeInstanceOf(Error);
            expect(err).toHaveProperty('message')
              .match(/"notBefore" should be a number of seconds or string representing a timespan/);
          });
        });
      });
    });

    // undefined needs special treatment because {} is not the same as {notBefore: undefined}
    it('should error with with value undefined', (done) => {
      testUtils.signJWTHelper({}, 'secret', {notBefore: undefined, algorithm: 'HS256'}, (err) => {
        testUtils.asyncCheck(done, () => {
          expect(err).toBeInstanceOf(Error);
          expect(err).toHaveProperty(
            'message',
            '"notBefore" should be a number of seconds or string representing a timespan'
          );
        });
      });
    });

    it('should error when "nbf" is in payload', (done) => {
      signWithNotBefore(100, {nbf: 100}, (err) => {
        testUtils.asyncCheck(done, () => {
          expect(err).toBeInstanceOf(Error);
          expect(err).toHaveProperty(
            'message',
            'Bad "options.notBefore" option the payload already has an "nbf" property.'
          );
        });
      });
    });

    it('should error with a string payload', (done) => {
      signWithNotBefore(100, 'a string payload', (err) => {
        testUtils.asyncCheck(done, () => {
          expect(err).toBeInstanceOf(Error);
          expect(err).toHaveProperty('message', 'invalid notBefore option for string payload');
        });
      });
    });

    it('should error with a Buffer payload', (done) => {
      signWithNotBefore(100, new Buffer('a Buffer payload'), (err) => {
        testUtils.asyncCheck(done, () => {
          expect(err).toBeInstanceOf(Error);
          expect(err).toHaveProperty('message', 'invalid notBefore option for object payload');
        });
      });
    });
  });

  describe('`jwt.sign` "nbf" claim validation', () => {
    [
      true,
      false,
      null,
      undefined,
      '',
      ' ',
      'invalid',
      [],
      ['foo'],
      {},
      {foo: 'bar'},
    ].forEach((nbf) => {
      it(`should error with with value ${util.inspect(nbf)}`, (done) => {
        signWithNotBefore(undefined, {nbf}, (err) => {
          testUtils.asyncCheck(done, () => {
            expect(err).toBeInstanceOf(Error);
            expect(err).toHaveProperty('message', '"nbf" should be a number of seconds');
          });
        });
      });
    });
  });

  describe('"nbf" in payload validation', () => {
    [
      true,
      false,
      null,
      -Infinity,
      Infinity,
      NaN,
      '',
      ' ',
      'invalid',
      [],
      ['foo'],
      {},
      {foo: 'bar'},
    ].forEach((nbf) => {
      it(`should error with with value ${util.inspect(nbf)}`, (done) => {
        const header = { alg: 'HS256' };
        const payload = { nbf };
        const token = jws.sign({ header, payload, secret: 'secret', encoding: 'utf8' });
        testUtils.verifyJWTHelper(token, 'secret', {nbf}, (err) => {
          testUtils.asyncCheck(done, () => {
            expect(err).toBeInstanceOf(jwt.JsonWebTokenError);
            expect(err).toHaveProperty('message', 'invalid nbf value');
          });
        });
      });
    })
  });

  describe('when signing and verifying a token with "notBefore" option', () => {
    let fakeClock;
    beforeEach(() => {
      fakeClock = jest.useFakeTimers();
    });

    afterEach(() => {
      fakeClock.uninstall();
    });

    it('should set correct "nbf" with negative number of seconds', (done) => {
      signWithNotBefore(-10, {}, (e1, token) => {
        testUtils.verifyJWTHelper(token, 'secret', {}, (e2, decoded) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).toBeNull();
            expect(e2).toBeNull();
            expect(decoded).toHaveProperty('nbf', 50);
          });
        })
      });
    });

    it('should set correct "nbf" with positive number of seconds', (done) => {
      signWithNotBefore(10, {}, (e1, token) => {
        fakeClock.tick(10000);
        testUtils.verifyJWTHelper(token, 'secret', {}, (e2, decoded) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).toBeNull();
            expect(e2).toBeNull();
            expect(decoded).toHaveProperty('nbf', 70);
          });
        })
      });
    });

    it('should set correct "nbf" with zero seconds', (done) => {
      signWithNotBefore(0, {}, (e1, token) => {
        testUtils.verifyJWTHelper(token, 'secret', {}, (e2, decoded) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).toBeNull();
            expect(e2).toBeNull();
            expect(decoded).toHaveProperty('nbf', 60);
          });
        })
      });
    });

    it('should set correct "nbf" with negative string timespan', (done) => {
      signWithNotBefore('-10 s', {}, (e1, token) => {
        testUtils.verifyJWTHelper(token, 'secret', {}, (e2, decoded) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).toBeNull();
            expect(e2).toBeNull();
            expect(decoded).toHaveProperty('nbf', 50);
          });
        })
      });
    });

    it('should set correct "nbf" with positive string timespan', (done) => {
      signWithNotBefore('10 s', {}, (e1, token) => {
        fakeClock.tick(10000);
        testUtils.verifyJWTHelper(token, 'secret', {}, (e2, decoded) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).toBeNull();
            expect(e2).toBeNull();
            expect(decoded).toHaveProperty('nbf', 70);
          });
        })
      });
    });

    it('should set correct "nbf" with zero string timespan', (done) => {
      signWithNotBefore('0 s', {}, (e1, token) => {
        testUtils.verifyJWTHelper(token, 'secret', {}, (e2, decoded) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).toBeNull();
            expect(e2).toBeNull();
            expect(decoded).toHaveProperty('nbf', 60);
          });
        })
      });
    });

    // TODO an nbf of -Infinity should fail validation
    it('should set null "nbf" when given -Infinity', (done) => {
      signWithNotBefore(undefined, {nbf: -Infinity}, (err, token) => {
        const decoded = jwt.decode(token);
        testUtils.asyncCheck(done, () => {
          expect(err).toBeNull();
          expect(decoded).toHaveProperty('nbf', null);
        });
      });
    });

    // TODO an nbf of Infinity should fail validation
    it('should set null "nbf" when given value Infinity', (done) => {
      signWithNotBefore(undefined, {nbf: Infinity}, (err, token) => {
        const decoded = jwt.decode(token);
        testUtils.asyncCheck(done, () => {
          expect(err).toBeNull();
          expect(decoded).toHaveProperty('nbf', null);
        });
      });
    });

    // TODO an nbf of NaN should fail validation
    it('should set null "nbf" when given value NaN', (done) => {
      signWithNotBefore(undefined, {nbf: NaN}, (err, token) => {
        const decoded = jwt.decode(token);
        testUtils.asyncCheck(done, () => {
          expect(err).toBeNull();
          expect(decoded).toHaveProperty('nbf', null);
        });
      });
    });

    it('should set correct "nbf" when "iat" is passed', (done) => {
      signWithNotBefore(-10, {iat: 40}, (e1, token) => {
        testUtils.verifyJWTHelper(token, 'secret', {}, (e2, decoded) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).toBeNull();
            expect(e2).toBeNull();
            expect(decoded).toHaveProperty('nbf', 30);
          });
        })
      });
    });

    it('should verify "nbf" using "clockTimestamp"', (done) => {
      signWithNotBefore(10, {}, (e1, token) => {
        testUtils.verifyJWTHelper(token, 'secret', {clockTimestamp: 70}, (e2, decoded) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).toBeNull();
            expect(e2).toBeNull();
            expect(decoded).toHaveProperty('iat', 60);
            expect(decoded).toHaveProperty('nbf', 70);
          });
        })
      });
    });

    it('should verify "nbf" using "clockTolerance"', (done) => {
      signWithNotBefore(5, {}, (e1, token) => {
        testUtils.verifyJWTHelper(token, 'secret', {clockTolerance: 6}, (e2, decoded) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).toBeNull();
            expect(e2).toBeNull();
            expect(decoded).toHaveProperty('iat', 60);
            expect(decoded).toHaveProperty('nbf', 65);
          });
        })
      });
    });

    it('should ignore a not active token when "ignoreNotBefore" is true', (done) => {
      signWithNotBefore('10 s', {}, (e1, token) => {
        testUtils.verifyJWTHelper(token, 'secret', {ignoreNotBefore: true}, (e2, decoded) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).toBeNull();
            expect(e2).toBeNull();
            expect(decoded).toHaveProperty('iat', 60);
            expect(decoded).toHaveProperty('nbf', 70);
          });
        })
      });
    });

    it('should error on verify if "nbf" is after current time', (done) => {
      signWithNotBefore(undefined, {nbf: 61}, (e1, token) => {
        testUtils.verifyJWTHelper(token, 'secret', {}, (e2) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).toBeNull();
            expect(e2).toBeInstanceOf(jwt.NotBeforeError);
            expect(e2).toHaveProperty('message', 'jwt not active');
          });
        })
      });
    });

    it('should error on verify if "nbf" is after current time using clockTolerance', (done) => {
      signWithNotBefore(5, {}, (e1, token) => {
        testUtils.verifyJWTHelper(token, 'secret', {clockTolerance: 4}, (e2) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).toBeNull();
            expect(e2).toBeInstanceOf(jwt.NotBeforeError);
            expect(e2).toHaveProperty('message', 'jwt not active');
          });
        })
      });
    });
  });
});
