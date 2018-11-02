'use strict';

const jwt = require('../');
const expect = require('chai').expect;
const util = require('util');
const testUtils = require('./test-utils');

function signWithKeyId(keyid, payload, callback) {
  const options = {algorithm: 'none'};
  if (keyid !== undefined) {
    options.keyid = keyid;
  }
  testUtils.signJWTHelper(payload, 'secret', options, callback);
}

describe('keyid', function() {
  describe('`jwt.sign` "keyid" option validation', function () {
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
    ].forEach((keyid) => {
      it(`should error with with value ${util.inspect(keyid)}`, function (done) {
        signWithKeyId(keyid, {}, (err) => {
          testUtils.asyncCheck(done, () => {
            expect(err).to.be.instanceOf(Error);
            expect(err).to.have.property('message', '"keyid" must be a string');
          });
        });
      });
    });

    // undefined needs special treatment because {} is not the same as {keyid: undefined}
    it('should error with with value undefined', function (done) {
      testUtils.signJWTHelper({}, undefined, {keyid: undefined, algorithm: 'none'}, (err) => {
        testUtils.asyncCheck(done, () => {
          expect(err).to.be.instanceOf(Error);
          expect(err).to.have.property('message', '"keyid" must be a string');
        });
      });
    });
  });

  describe('when signing a token', function () {
    it('should not add "kid" header when "keyid" option not provided', function(done) {
      signWithKeyId(undefined, {}, (err, token) => {
        testUtils.asyncCheck(done, () => {
          const decoded = jwt.decode(token, {complete: true});
          expect(err).to.be.null;
          expect(decoded.header).to.not.have.property('kid');
        });
      });
    });

    it('should add "kid" header when "keyid" option is provided and an object payload', function(done) {
      signWithKeyId('foo', {}, (err, token) => {
        testUtils.asyncCheck(done, () => {
          const decoded = jwt.decode(token, {complete: true});
          expect(err).to.be.null;
          expect(decoded.header).to.have.property('kid', 'foo');
        });
      });
    });

    it('should add "kid" header when "keyid" option is provided and a Buffer payload', function(done) {
      signWithKeyId('foo', new Buffer('a Buffer payload'), (err, token) => {
        testUtils.asyncCheck(done, () => {
          const decoded = jwt.decode(token, {complete: true});
          expect(err).to.be.null;
          expect(decoded.header).to.have.property('kid', 'foo');
        });
      });
    });

    it('should add "kid" header when "keyid" option is provided and a string payload', function(done) {
      signWithKeyId('foo', 'a string payload', (err, token) => {
        testUtils.asyncCheck(done, () => {
          const decoded = jwt.decode(token, {complete: true});
          expect(err).to.be.null;
          expect(decoded.header).to.have.property('kid', 'foo');
        });
      });
    });
  });
});
