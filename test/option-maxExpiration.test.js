'use strict';

const jwt = require('..');
const expect = require('chai').expect;
const sinon = require('sinon');
const util = require('util');

describe('maxExpiration option', function() {
  let token;

  let fakeClock;
  beforeEach(function() {
    fakeClock = sinon.useFakeTimers({now: 60000});
    token = jwt.sign({iat: 70}, undefined, {algorithm: 'none', expiresIn: '2s'});
  });

  afterEach(function() {
    fakeClock.uninstall();
  });

  [
    {
      description: 'should work with a positive string value',
      maxExpiration: '3s',
    },
    {
      description: 'should work with a positive numeric value',
      maxExpiration: 3,
    }
  ].forEach((testCase) => {
    it(testCase.description, function (done) {
      expect(jwt.verify(token, undefined, {maxExpiration: '3s'})).to.not.throw;
      jwt.verify(token, undefined, {maxExpiration: testCase.maxExpiration}, (err) => {
        expect(err).to.be.null;
        done();
      })
    });
  });

  [
    {
      description: 'should error with a negative string value',
      maxExpiration: '-3s',
    },
    {
      description: 'should error with a negative numeric value',
      maxExpiration: -3,
    },
    {
      description: 'should error with a positive value less than tokens exp',
      maxExpiration: '1s',
    },
    {
      description: 'should error with a negative value less than tokens exp',
      maxExpiration: '-3s',
    }
  ].forEach((testCase) => {
    it(testCase.description, function (done) {
      expect(() => jwt.verify(token, undefined, {maxExpiration: testCase.maxExpiration})).to.throw(
        jwt.JsonWebTokenError,
        'jwt expiration is longer then the specified maxExpiration: ' + testCase.maxExpiration
      );
      jwt.verify(token, undefined, {maxExpiration: testCase.maxExpiration}, (err) => {
        expect(err).to.be.instanceOf(jwt.JsonWebTokenError);
        expect(err.message).to.equal(
          'jwt expiration is longer then the specified maxExpiration: ' + testCase.maxExpiration
        );
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
    {foo: 'bar'},
  ].forEach((maxExpiration) => {
    it(`should error with value ${util.inspect(maxExpiration)}`, function (done) {
      expect(() => jwt.verify(token, undefined, {maxExpiration})).to.throw(
        jwt.JsonWebTokenError,
        '"maxExpiration" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60'
      );
      jwt.verify(token, undefined, {maxExpiration}, (err) => {
        expect(err).to.be.instanceOf(jwt.JsonWebTokenError);
        expect(err.message).to.equal(
          '"maxExpiration" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60'
        );
        done();
      })
    });
  });
});
