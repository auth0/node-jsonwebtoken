'use strict';

const jwt = require('../');
const expect = require('chai').expect;
const util = require('util');

describe('nonce option', function () {
  let token;

  beforeEach(function () {
    token = jwt.sign({ nonce: 'abcde' }, undefined, { algorithm: 'none' });
  });
  [
    {
      description: 'should work with string',
      nonce: 'abcde',
    },
  ].forEach((testCase) => {
    it(testCase.description, function (done) {
      expect(jwt.verify(token, undefined, { nonce: testCase.nonce })).to.not.throw;
      jwt.verify(token, undefined, { nonce: testCase.nonce }, (err) => {
        expect(err).to.be.null;
        done();
      })
    });
  });
  [
    true,
    'invalid',
    [],
    ['foo'],
    {},
    { foo: 'bar' },
  ].forEach((nonce) => {
    let tokenhoge = jwt.sign({ foo: 'bar' }, undefined, { algorithm: 'none' });
    it(`should error with value ${util.inspect(nonce)}`, function (done) {
      expect(() => jwt.verify(tokenhoge, undefined, { nonce: nonce })).to.throw(
        jwt.JsonWebTokenError,
        'jwt nonce invalid. expected: ' + nonce
      );
      jwt.verify(tokenhoge, undefined, { nonce: nonce }, (err) => {
        expect(err).to.be.instanceOf(jwt.JsonWebTokenError);
        expect(err.message).to.equal(
          'jwt nonce invalid. expected: ' + nonce
        );
        done();
      })
    });
  });
});
