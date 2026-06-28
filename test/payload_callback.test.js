'use strict';

const jwt = require('../index');
const assert = require('chai').assert;
const expect = require('chai').expect;

describe('payload callback', function() {
  const KEY = 'somethingSECRET';
  const TEST_ERROR_MESSAGE = 'bar not car!';
  let testPayloadCallback;

  beforeEach(function() {
    testPayloadCallback = function (payload) {
      if (payload.foo !== 'bar') {
        throw new Error(TEST_ERROR_MESSAGE);
      }
    }
  });

  it('should check that the payload satisfies the provided callback', function () {
    const token = jwt.sign({ foo: 'bar' }, KEY);
    const result = jwt.verify(token, KEY, undefined, undefined, testPayloadCallback);
    expect(result.foo).to.equal('bar');
  });

  it('should be compatible with async token verification', function () {
    const testCallback = function (err, decoded) {
      if (err) {
        assert.fail(err.message);
      }
      expect(decoded.foo).to.equal('bar');
    }

    const token = jwt.sign({ foo: 'bar' }, KEY);
    jwt.verify(token, KEY, {}, testCallback, testPayloadCallback);
  });

  it('should throw when the payload callback rejects', function () {
    const token = jwt.sign({ foo: 'car' }, KEY);
    expect(function () {
      jwt.verify(token, KEY, undefined, undefined, testPayloadCallback)
    }).to.throw(TEST_ERROR_MESSAGE);
  })
})