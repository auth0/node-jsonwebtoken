var semver = require('semver');

/**
 * Checks if the current Node.js version is supported by this library.
 *
 * @returns {boolean}
 */

module.exports = semver.satisfies(process.version, '^6.12.0 || >=8.0.0');
