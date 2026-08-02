'use strict';

const jwt = require('../');
const expect = require('chai').expect;
const util = require('util');
const testUtils = require('./test-utils');

function signWithCrit(crit, extraHeader) {
  const header = Object.assign({}, extraHeader);
  if (crit !== undefined) {
    header.crit = crit;
  }
  return jwt.sign({sub: 'foo'}, 'secret', {algorithm: 'HS256', header});
}

describe('crit', function () {
  describe('`jwt.verify` with a "crit" header parameter', function () {
    [
      // an extension nobody implements
      ['http://example.invalid/UNDEFINED'],
      // RFC 7797 unencoded payload: a conformant verifier reads a different payload
      ['b64'],
      // names the producer is not even allowed to mark critical
      ['alg'],
      // shapes RFC 7515 forbids producers from emitting
      [],
      'b64',
      1,
      null,
      {},
    ].forEach((crit) => {
      it(`should error with value ${util.inspect(crit)}`, function (done) {
        const token = signWithCrit(crit, {'http://example.invalid/UNDEFINED': true, b64: false});
        testUtils.verifyJWTHelper(token, 'secret', {}, (err) => {
          testUtils.asyncCheck(done, () => {
            expect(err).to.be.instanceOf(jwt.JsonWebTokenError);
            expect(err).to.have.property('message', 'unsupported "crit" header parameter');
          });
        });
      });
    });

    it('should error before the "complete" option can expose the payload', function (done) {
      const token = signWithCrit(['http://example.invalid/UNDEFINED']);
      testUtils.verifyJWTHelper(token, 'secret', {complete: true}, (err, decoded) => {
        testUtils.asyncCheck(done, () => {
          expect(err).to.be.instanceOf(jwt.JsonWebTokenError);
          expect(err).to.have.property('message', 'unsupported "crit" header parameter');
          expect(decoded).to.be.undefined;
        });
      });
    });
  });

  describe('`jwt.verify` without a "crit" header parameter', function () {
    it('should verify a token that has no "crit" header', function (done) {
      const token = signWithCrit(undefined);
      testUtils.verifyJWTHelper(token, 'secret', {}, (err, decoded) => {
        testUtils.asyncCheck(done, () => {
          expect(err).to.be.null;
          expect(decoded).to.have.property('sub', 'foo');
        });
      });
    });

    it('should verify a token with unrecognized headers that are not marked critical', function (done) {
      const token = signWithCrit(undefined, {'http://example.invalid/UNDEFINED': true});
      testUtils.verifyJWTHelper(token, 'secret', {}, (err, decoded) => {
        testUtils.asyncCheck(done, () => {
          expect(err).to.be.null;
          expect(decoded).to.have.property('sub', 'foo');
        });
      });
    });
  });

  describe('`jwt.decode`', function () {
    it('should still decode a token with a "crit" header, as it does not verify', function () {
      const token = signWithCrit(['http://example.invalid/UNDEFINED']);
      const decoded = jwt.decode(token, {complete: true});
      expect(decoded.header).to.have.deep.property('crit', ['http://example.invalid/UNDEFINED']);
      expect(decoded.payload).to.have.property('sub', 'foo');
    });
  });
});
