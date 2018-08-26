'use strict';

const jwt = require('../');
const expect = require('chai').expect;
const sinon = require('sinon');
const util = require('util');

describe('maxAge option', function() {
  let token;

  let fakeClock;
  beforeEach(function() {
    fakeClock = sinon.useFakeTimers({now: 60000});
    token = jwt.sign({iat: 70}, undefined, {algorithm: 'none'});
  });

  afterEach(function() {
    fakeClock.uninstall();
  });

  [
    {
      description: 'should work with a positive string value',
      maxAge: '3s',
    },
    {
      description: 'should work with a negative string value',
      maxAge: '-3s',
    },
    {
      description: 'should work with a positive numeric value',
      maxAge: 3,
    },
    {
      description: 'should work with a negative numeric value',
      maxAge: -3,
    },
  ].forEach((testCase) => {
    it(testCase.description, function (done) {
      expect(jwt.verify(token, undefined, {maxAge: '3s'})).to.not.throw;
      jwt.verify(token, undefined, {maxAge: testCase.maxAge}, (err) => {
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
    {foo: 'bar'},
  ].forEach((maxAge) => {
    it(`should error with value ${util.inspect(maxAge)}`, function (done) {
      expect(() => jwt.verify(token, undefined, {maxAge})).to.throw(
        jwt.JsonWebTokenError,
        '"maxAge" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60'
      );
      jwt.verify(token, undefined, {maxAge}, (err) => {
        expect(err).to.be.instanceOf(jwt.JsonWebTokenError);
        expect(err.message).to.equal(
          '"maxAge" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60'
        );
        done();
      })
    });
  });
});
