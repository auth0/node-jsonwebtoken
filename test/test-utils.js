'use strict';

const jwt = require('../');

/**
 * Correctly report errors that occur in an asynchronous callback
 * @param {function(err): void} done The Jest callback
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
function expectEqualError(e1, e2) {
  // message and name are not always enumerable, so manually reference them
  expect(e1.message).toBe(e2.message);
  expect(e1.name).toBe(e2.name);

  // compare other enumerable error properties
  for(const propertyName in e1) {
    expect(e1[propertyName]).toEqual(e2[propertyName]);
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
 * Verify a JWT using the async API
 * @param {string} jwtString The JWT as a string
 * @param {string} secretOrPrivateKey The shared secret or private key
 * @param {object} options Verify options
 * @returns {Promise<any>} The decoded token or throws an error
 */
async function verifyJWTHelper(jwtString, secretOrPrivateKey, options) {
  // freeze the time to ensure the clock remains stable
  jest.useFakeTimers();
  jest.setSystemTime(Date.now());

  try {
    const verified = await jwt.verify(jwtString, secretOrPrivateKey, options);
    return verified;
  }
  finally {
    jest.useRealTimers();
  }
}

/**
 * Sign a payload to create a JWT using the async API
 * @param {object} payload The JWT payload
 * @param {string} secretOrPrivateKey The shared secret or private key
 * @param {object} options Sign options
 * @returns {Promise<string>} The signed JWT or throws an error
 */
async function signJWTHelper(payload, secretOrPrivateKey, options) {
  // freeze the time to ensure the clock remains stable
  jest.useFakeTimers();
  jest.setSystemTime(Date.now());

  try {
    const signed = await jwt.sign(payload, secretOrPrivateKey, options);
    return signed;
  }
  finally {
    jest.useRealTimers();
  }
}

module.exports = {
  asyncCheck,
  base64UrlEncode,
  signJWTHelper,
  verifyJWTHelper,
};
