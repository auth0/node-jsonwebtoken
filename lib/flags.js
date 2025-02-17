/* istanbul ignore file */
const [major, minor] = process.versions.node.split('.').map((v) => parseInt(v, 10));

module.exports.RSA_PSS_KEY_DETAILS_SUPPORTED = major > 16 || (major === 16 && minor >= 9);
module.exports.ASYMMETRIC_KEY_DETAILS_SUPPORTED = major > 15 || (major === 15 && minor >= 7);
