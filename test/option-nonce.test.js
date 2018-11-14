'use strict';

const jwt = require('../');
const expect = require('chai').expect;
const util = require('util');
const testUtils = require('./test-utils')

describe('nonce option', function () {
  let token;

  beforeEach(function () {
    token = jwt.sign({ nonce: 'abcde' }, undefined, { algorithm: 'none' });
  });
  [
    {
      description: 'should work with a string',
      nonce: 'abcde',
    },
  ].forEach((testCase) => {
    it(testCase.description, function (done) {
      testUtils.verifyJWTHelper(token, undefined, { nonce: testCase.nonce }, (err, decoded) => {
        testUtils.asyncCheck(done, () => {
          expect(err).to.be.null;
          expect(decoded).to.have.property('nonce', 'abcde');
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
    it(`should error with value ${util.inspect(nonce)}`, function (done) {
      testUtils.verifyJWTHelper(token, undefined, { nonce }, (err) => {
        testUtils.asyncCheck(done, () => {
          expect(err).to.be.instanceOf(jwt.JsonWebTokenError);
          expect(err).to.have.property('message', 'nonce must be a non-empty string')
        });
      });
    });
  });
});
