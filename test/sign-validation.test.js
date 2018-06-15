'use strict';

const jwt = require('../');
const expect = require('chai').expect;
const fs = require('fs');
const path = require('path');

describe('sign validation', function() {
  const validRSAPrivateCertificate = fs.readFileSync(path.resolve(__dirname, 'rsa-private.pem'));
  const validECDSAPrivateCertificate = fs.readFileSync(path.resolve(__dirname, 'ecdsa-private.pem'));

  describe('for options', function() {
    [
      {
        description: 'with valid integer "expiresIn"',
        options: {expiresIn: 10}
      },
      {
        description: 'with valid string "expiresIn"',
        options: {expiresIn: '10 m'}
      },
      {
        description: 'with valid integer "notBefore"',
        options: {notBefore: 10}
      },
      {
        description: 'with valid string "notBefore"',
        options: {notBefore: '10 m'}
      },
      {
        description: 'with valid array "audience"',
        options: {audience: ['audience1', 'audience2']}
      },
      {
        description: 'with valid array "audience"',
        options: {audience: ['audience1', 'audience2']}
      },
      {
        description: 'with valid object "header"',
        options: {header: {custom: 'value'}}
      },
      {
        description: 'with valid string "encoding"',
        options: {encoding: 'utf8'}
      },
      {
        description: 'with valid string "issuer"',
        options: {issuer: 'issuer'}
      },
      {
        description: 'with valid string "subject"',
        options: {subject: 'subject'}
      },
      {
        description: 'with valid string "jwtid"',
        options: {jwtid: 'jwtid'}
      },
      {
        description: 'with valid boolean "noTimestamp"',
        options: {noTimestamp: true}
      },
      {
        description: 'with valid string "keyid"',
        options: {keyid: 'keyid'}
      },
      {
        description: 'with valid boolean "mutatePayload"',
        options: {mutatePayload: true}
      },
    ].forEach((testCase) => {
      it(`should not error ${testCase.description}`, function() {
        expect(jwt.sign({}, 'secret', testCase.options)).to.not.throw;
      });
    });

    [
      'RS256', 'RS384', 'RS512'
    ].forEach((algorithm) => {
      it(`should not error with algorithm "${algorithm}"`, function() {
        expect(jwt.sign({foo: 'bar'}, validRSAPrivateCertificate, {algorithm})).to.not.throw;
      });
    });

    [
      'ES256', 'ES384', 'ES512'
    ].forEach((algorithm) => {
      it(`should not error with algorithm "${algorithm}"`, function() {
        expect(jwt.sign({foo: 'bar'}, validECDSAPrivateCertificate, {algorithm})).to.not.throw;
      });
    });

    [
      'HS256', 'HS384', 'HS512', 'none'
    ].forEach((algorithm) => {
      it(`should not error with algorithm "${algorithm}"`, function() {
        expect(jwt.sign({foo: 'bar'}, 'secret', {algorithm})).to.not.throw;
      });
    });

    [
      {
        description: 'when not passed an object',
        options: 'not an object',
        expectedError: 'Expected "options" to be a plain object.'
      },
      {
        description: 'when passed an unknown option',
        options: {invalid: 'value'},
        expectedError: '"invalid" is not allowed in "options"'
      },
      {
        description: 'when passed the deprecated "expiresInSeconds" option',
        options: {expiresInSeconds: 'value'},
        expectedError: '"expiresInSeconds" is not allowed in "options"'
      },
      {
        description: 'with "expiresIn" as a string with an invalid unit',
        options: {expiresIn: '1 monkey'},
        expectedError: '"expiresIn" should be a number of seconds or string representing a timespan'
      },
      {
        description: 'with "expiresIn" as a float',
        options: {expiresIn: 1.1},
        expectedError: '"expiresIn" should be a number of seconds or string representing a timespan'
      },
      {
        description: 'when "expiresIn" is provided with "exp" in payload',
        options: {expiresIn: 100},
        payload: {exp: 200},
        expectedError: 'Bad "options.expiresIn" option the payload already has an "exp" property.'
      },
      {
        description: 'with "notBefore" as a string with an invalid unit',
        options: {notBefore: '1 monkey'},
        expectedError: '"notBefore" should be a number of seconds or string representing a timespan'
      },
      {
        description: 'with "notBefore" as a float',
        options: {notBefore: 1.1},
        expectedError: '"notBefore" should be a number of seconds or string representing a timespan'
      },
      {
        description: 'when "notBefore" is provided with "nbf" in payload',
        options: {notBefore: 100},
        payload: {nbf: 200},
        expectedError: 'Bad "options.notBefore" option the payload already has an "nbf" property.'
      },
      {
        description: 'with a non-string or non-array "audience"',
        options: {audience: 10},
        expectedError: '"audience" must be a string or array'
      },
      {
        description: 'when "audience" is provided with "aud" in payload',
        options: {audience: 'audience'},
        payload: {aud: 'aud'},
        expectedError: 'Bad "options.audience" option. The payload already has an "aud" property.'
      },
      {
        description: 'with a "algorithm" not in allowed list',
        options: {algorithm: 'invalid'},
        expectedError: '"algorithm" must be a valid string enum value'
      },
      {
        description: 'with a non-object "header"',
        options: {header: 'invalid'},
        expectedError: '"header" must be an object'
      },
      {
        description: 'with a non-string "encoding"',
        options: {encoding: 10},
        expectedError: '"encoding" must be a string'
      },
      {
        description: 'with a non-string "issuer"',
        options: {issuer: 10},
        expectedError: '"issuer" must be a string'
      },
      {
        description: 'when "issuer" is provided with "iss" in payload',
        options: {issuer: 'issuer'},
        payload: {iss: 'iss'},
        expectedError: 'Bad "options.issuer" option. The payload already has an "iss" property.'
      },
      {
        description: 'with a non-string "subject"',
        options: {subject: 10},
        expectedError: '"subject" must be a string'
      },
      {
        description: 'when "subject" is provided with "sub" in payload',
        options: {subject: 'subject'},
        payload: {sub: 'sub'},
        expectedError: 'Bad "options.subject" option. The payload already has an "sub" property.'
      },
      {
        description: 'with a non-string "jwtid"',
        options: {jwtid: 10},
        expectedError: '"jwtid" must be a string'
      },
      {
        description: 'when "jwtid" is provided with "jti" in payload',
        options: {jwtid: 'jwtid'},
        payload: {jti: 'jti'},
        expectedError: 'Bad "options.jwtid" option. The payload already has an "jti" property.'
      },
      {
        description: 'with a non-boolean "noTimestamp"',
        options: {noTimestamp: 'invalid'},
        expectedError: '"noTimestamp" must be a boolean'
      },
      {
        description: 'with a non-string "keyid"',
        options: {keyid: 10},
        expectedError: '"keyid" must be a string'
      },
      {
        description: 'with a non-string "keyid"',
        options: {keyid: 10},
        expectedError: '"keyid" must be a string'
      },
      {
        description: 'with a non-string "mutatePayload"',
        options: {mutatePayload: 'invalid'},
        expectedError: '"mutatePayload" must be a boolean'
      }
    ].forEach((testCase) => {
      it(`should error ${testCase.description}`, function() {
        expect(() => jwt.sign(testCase.payload || {}, 'secret', testCase.options)).to.throw(testCase.expectedError);
      });
    });
  });

  describe('for options with non-object payload', function() {
    it('should not error with valid options on string payload', function() {
      expect(jwt.sign('a string payload', 'secret', {
        algorithm: 'HS256',
        header: {custom: 'value'},
        encoding: 'utf8',
        keyid: 'keyid',
        mutatePayload: false
      })).to.not.throw;
    });

    it('should not error with valid options on Buffer payload', function() {
      expect(jwt.sign(new Buffer('a Buffer payload'), 'secret', {
        algorithm: 'HS256',
        header: {custom: 'value'},
        encoding: 'utf8',
        keyid: 'keyid',
        mutatePayload: false
      })).to.not.throw;
    });

    [
      {
        description: 'when provided "expiresIn"',
        options: {expiresIn: 10},
        expectedErrorOptions: 'expiresIn'
      },
      {
        description: 'when provided "notBefore"',
        options: {notBefore: 10},
        expectedErrorOptions: 'notBefore'
      },
      {
        description: 'when provided "noTimestamp"',
        options: {noTimestamp: true},
        expectedErrorOptions: 'noTimestamp'
      },
      {
        description: 'when provided "audience"',
        options: {audience: 'audience'},
        expectedErrorOptions: 'audience'
      },
      {
        description: 'when provided "issuer"',
        options: {issuer: 'issuer'},
        expectedErrorOptions: 'issuer'
      },
      {
        description: 'when provided "subject"',
        options: {subject: 'subject'},
        expectedErrorOptions: 'subject'
      },
      {
        description: 'when provided "jwtid"',
        options: {jwtid: 'jwtid'},
        expectedErrorOptions: 'jwtid'
      },
      {
        description: 'when all provided options',
        options: {
          expiresIn: 'expiresIn',
          notBefore: 'notBefore',
          noTimestamp: 'noTimestamp',
          audience: 'audience',
          issuer: 'issuer',
          subject: 'subject',
          jwtid: 'jwtid'
        },
        expectedErrorOptions: 'expiresIn,notBefore,noTimestamp,audience,issuer,subject,jwtid'
      }
    ].forEach((testCase) => {
      it(`should error with a string payload ${testCase.description}`, function() {
        expect(() => jwt.sign('a string payload', 'secret', testCase.options))
          .to.throw(`invalid ${testCase.expectedErrorOptions} option for string payload`);
      });
      it(`should error with a Buffer payload ${testCase.description}`, function() {
        expect(() => jwt.sign(new Buffer('a Buffer payload'), 'secret', testCase.options))
          .to.throw(`invalid ${testCase.expectedErrorOptions} option for object payload`);
      });
    });
  });

  describe('for payload', function() {
    it('should not error with valid payload', function() {
      expect(jwt.sign({foo: 'bar'}, 'secret')).to.not.throw;
    });

    [
      {
        description: 'when provided an undefined payload',
        payload: undefined,
        expectedError: 'payload is required'
      },
      {
        description: 'with a non-number "iat" claim',
        payload: {iat: 'invalid'},
        expectedError: '"iat" should be a number of seconds'
      },
      {
        description: 'with a non-number "exp" claim',
        payload: {exp: 'invalid'},
        expectedError: '"exp" should be a number of seconds'
      },
      {
        description: 'with a non-string "nbf" claim',
        payload: {nbf: 'invalid'},
        expectedError: '"nbf" should be a number of seconds'
      }
    ].forEach((testCase) => {
      it(`should error ${testCase.description}`, function() {
        expect(() => jwt.sign(testCase.payload, 'secret', {})).to.throw(testCase.expectedError);
      });
    });
  });

  describe('for a secretOrPrivateKey with algorithm not set to "none"', function () {
    it('should not error with valid secret', function() {
      expect(jwt.sign({foo: 'bar'}, 'secret')).to.not.throw;
    });

    it('should not error with valid private key', function() {
      expect(jwt.sign({foo: 'bar'}, validRSAPrivateCertificate, {algorithm: 'RS256'})).to.not.throw;
    });

    [
      undefined, null, '', 0, NaN, false
    ].forEach((secretOrPrivateKey) => {
      it(`should error with key "${secretOrPrivateKey}" with type "${typeof secretOrPrivateKey}"`, function() {
        expect(() => jwt.sign({}, secretOrPrivateKey)).to.throw('secretOrPrivateKey must have a value');
      })
    });
  });
});
