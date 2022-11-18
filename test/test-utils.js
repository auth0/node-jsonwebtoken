'use strict';

const jwt = require('../');
const expect = require('chai').expect;
const sinon = require('sinon');

/**
 * Correctly report errors that occur in an asynchronous callback
 * @param {function(err): void} done The mocha callback
 * @param {function(): void} testFunction The assertions function
 */
function asyncCheck(done, testFunction) {
  try {
    testFunction();
    done();
  }
  catch(err) {
    done(err);
  }
}

/**
 * Assert that two errors are equal
 * @param e1 {Error} The first error
 * @param e2 {Error} The second error
 */
// chai does not do deep equality on errors: https://github.com/chaijs/chai/issues/1009
function expectEqualError(e1, e2) {
  // message and name are not always enumerable, so manually reference them
  expect(e1.message, 'Async/Sync Error equality: message').to.equal(e2.message);
  expect(e1.name, 'Async/Sync Error equality: name').to.equal(e2.name);

  // compare other enumerable error properties
  for(const propertyName in e1) {
    expect(e1[propertyName], `Async/Sync Error equality: ${propertyName}`).to.deep.equal(e2[propertyName]);
  }
}

/**
 * Base64-url encode a string
 * @param str {string} The string to encode
 * @returns {string} The encoded string
 */
function base64UrlEncode(str) {
  return Buffer.from(str).toString('base64')
    .replace(/[=]/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
  ;
}

/**
 * Verify a JWT, ensuring that the asynchronous and synchronous calls to `verify` have the same result
 * @param {string} jwtString The JWT as a string
 * @param {string} secretOrPrivateKey The shared secret or private key
 * @param {object} options Verify options
 * @param {function(err, token):void} callback
 */
function verifyJWTHelper(jwtString, secretOrPrivateKey, options, callback) {
  // freeze the time to ensure the clock remains stable across the async and sync calls
  const fakeClock = sinon.useFakeTimers({now: Date.now()});
  let error;
  let syncVerified;
  try {
    syncVerified = jwt.verify(jwtString, secretOrPrivateKey, options);
  }
  catch (err) {
    error = err;
  }
  jwt.verify(jwtString, secretOrPrivateKey, options, (err, asyncVerifiedToken) => {
    try {
      if (error) {
        expectEqualError(err, error);
        callback(err);
      }
      else {
        expect(syncVerified, 'Async/Sync token equality').to.deep.equal(asyncVerifiedToken);
        callback(null, syncVerified);
      }
    }
    finally {
      if (fakeClock) {
        fakeClock.restore();
      }
    }
  });
}

/**
 * Sign a payload to create a JWT, ensuring that the asynchronous and synchronous calls to `sign` have the same result
 * @param {object} payload The JWT payload
 * @param {string} secretOrPrivateKey The shared secret or private key
 * @param {object} options Sign options
 * @param {function(err, token):void} callback
 */
function signJWTHelper(payload, secretOrPrivateKey, options, callback) {
  // freeze the time to ensure the clock remains stable across the async and sync calls
  const fakeClock = sinon.useFakeTimers({now: Date.now()});
  let error;
  let syncSigned;
  try {
    syncSigned = jwt.sign(payload, secretOrPrivateKey, options);
  }
  catch (err) {
    error = err;
  }
  jwt.sign(payload, secretOrPrivateKey, options, (err, asyncSigned) => {
    fakeClock.restore();
    if (error) {
      expectEqualError(err, error);
      callback(err);
    }
    else {
      expect(syncSigned, 'Async/Sync token equality').to.equal(asyncSigned);
      callback(null, syncSigned);
    }
  });
}

module.exports = {
  asyncCheck,
  base64UrlEncode,
  signJWTHelper,
  verifyJWTHelper,
};
