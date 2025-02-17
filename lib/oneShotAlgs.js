const { constants } = require("crypto");

module.exports = function(alg, key) {
  switch (alg) {
  case 'RS256':
    return {
      digest: 'sha256',
      key: { key, padding: constants.RSA_PKCS1_PADDING },
    };
  case 'RS384':
    return {
      digest: 'sha384',
      key: { key, padding: constants.RSA_PKCS1_PADDING },
    };
  case 'RS512':
    return {
      digest: 'sha512',
      key: { key, padding: constants.RSA_PKCS1_PADDING },
    };
  case 'PS256':
    return {
      digest: 'sha256',
      key: { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: constants.RSA_PSS_SALTLEN_DIGEST },
    };
  case 'PS384':
    return {
      digest: 'sha384',
      key: { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: constants.RSA_PSS_SALTLEN_DIGEST },
    };
  case 'PS512':
    return {
      digest: 'sha512',
      key: { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: constants.RSA_PSS_SALTLEN_DIGEST },
    };
  case 'ES256':
    return {
      digest: 'sha256',
      key: { key, dsaEncoding: 'ieee-p1363' },
    };
  case 'ES256K':
    return {
      digest: 'sha256',
      key: { key, dsaEncoding: 'ieee-p1363' },
    };
  case 'ES384':
    return {
      digest: 'sha384',
      key: { key, dsaEncoding: 'ieee-p1363' },
    };
  case 'ES512':
    return {
      digest: 'sha512',
      key: { key, dsaEncoding: 'ieee-p1363' },
    };
  case 'Ed25519':
  case 'Ed448':
  case 'EdDSA':
    return {
      digest: undefined,
      key: { key },
    };
  default:
    throw new Error('unreachable');
  }
};
