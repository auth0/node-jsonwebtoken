'use strict';

const expect = require('chai').expect;
const util = require('util');
const testUtils = require('./test-utils');

function signWithPayload(payload, callback) {
  testUtils.signJWTHelper(payload, 'secret', {algorithm: 'none'}, callback);
}

describe('with a private claim', function() {
  [
    true,
    false,
    null,
    -1,
    0,
    1,
    -1.1,
    1.1,
    '',
    'private claim',
    'UTF8 - José',
    [],
    ['foo'],
    {},
    {foo: 'bar'},
  ].forEach((privateClaim) => {
    it(`should sign and verify with claim of ${util.inspect(privateClaim)}`, function (done) {
      signWithPayload({privateClaim}, (e1, token) => {
        testUtils.verifyJWTHelper(token, undefined, {}, (e2, decoded) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).to.be.null;
            expect(e2).to.be.null;
            expect(decoded).to.have.property('privateClaim').to.deep.equal(privateClaim);
          });
        })
      });
    });
  });

  // these values JSON.stringify to null
  [
    -Infinity,
    Infinity,
    NaN,
  ].forEach((privateClaim) => {
    it(`should sign and verify with claim of ${util.inspect(privateClaim)}`, function (done) {
      signWithPayload({privateClaim}, (e1, token) => {
        testUtils.verifyJWTHelper(token, undefined, {}, (e2, decoded) => {
          testUtils.asyncCheck(done, () => {
            expect(e1).to.be.null;
            expect(e2).to.be.null;
            expect(decoded).to.have.property('privateClaim', null);
          });
        })
      });
    });
  });

  // private claims with value undefined are not added to the payload
  it(`should sign and verify with claim of undefined`, function (done) {
    signWithPayload({privateClaim: undefined}, (e1, token) => {
      testUtils.verifyJWTHelper(token, undefined, {}, (e2, decoded) => {
        testUtils.asyncCheck(done, () => {
          expect(e1).to.be.null;
          expect(e2).to.be.null;
          expect(decoded).to.not.have.property('privateClaim');
        });
      })
    });
  });
});
