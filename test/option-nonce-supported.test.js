'use strict';

const jwt = require('../');
const expect = require('chai').expect;
const testUtils = require('./test-utils')

describe('nonce and nonce_supported option', function () {

  [
    {
      description: 'should succeed without nonce and without nonce support',
      signParam: { nonce_supported: false },
      verifyParam: { },
    },
    {
      description: 'should succeed without nonce but with nonce support',
      signParam: { nonce_supported: true },
      verifyParam: { },
    },
    {
      description: 'should succeed with nonce but without nonce support',
      signParam: { nonce_supported: false },
      verifyParam: { nonce: 'abcde' },
    },
    {
      description: 'should succeed with nonce and nonce support',
      signParam: { nonce: 'abcde', nonce_supported: true },
      verifyParam: { nonce: 'abcde' },
    },
  ].forEach((testCase) => {
    it(testCase.description, function (done) {
      var token = jwt.sign(testCase.signParam, undefined, { algorithm: 'none' });
      testUtils.verifyJWTHelper(token, undefined, testCase.verifyParam, (err) => {
        testUtils.asyncCheck(done, () => {
          expect(err).to.be.null;
        });
      });
    });
  });

});
