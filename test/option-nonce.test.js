'use strict';

const jwt = require('../');
const util = require('util');
const testUtils = require('./test-utils')

describe('nonce option', () => {
  let token;

  beforeEach(() => {
    token = jwt.sign({ nonce: 'abcde' }, 'secret', { algorithm: 'HS256' });
  });
  [
    {
      description: 'should work with a string',
      nonce: 'abcde',
    },
  ].forEach((testCase) => {
    it(testCase.description, (done) => {
      testUtils.verifyJWTHelper(token, 'secret', { nonce: testCase.nonce }, (err, decoded) => {
        testUtils.asyncCheck(done, () => {
          expect(err).toBeNull();
          expect(decoded).toHaveProperty('nonce', 'abcde');
        });
      });
    });
  });
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
    '',
    ' ',
    [],
    ['foo'],
    {},
    { foo: 'bar' },
  ].forEach((nonce) => {
    it(`should error with value ${util.inspect(nonce)}`, (done) => {
      testUtils.verifyJWTHelper(token, 'secret', { nonce }, (err) => {
        testUtils.asyncCheck(done, () => {
          expect(err).toBeInstanceOf(jwt.JsonWebTokenError);
          expect(err).toHaveProperty('message', 'nonce must be a non-empty string')
        });
      });
    });
  });
});
