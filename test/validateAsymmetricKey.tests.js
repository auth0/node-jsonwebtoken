const validateAsymmetricKey = require('../lib/validateAsymmetricKey');
const PS_SUPPORTED = require('../lib/psSupported');
const ASYMMETRIC_KEY_DETAILS_SUPPORTED = require('../lib/asymmetricKeyDetailsSupported');
const RSA_PSS_KEY_DETAILS_SUPPORTED = require('../lib/rsaPssKeyDetailsSupported');
const fs = require('fs');
const path = require('path');
const { createPrivateKey } = require('crypto');
const expect = require('chai').expect;

function loadKey(filename) {
  return createPrivateKey(
    fs.readFileSync(path.join(__dirname, filename))
  );
}

const algorithmParams = {
  RS256: {
    invalidPrivateKey: loadKey('secp384r1-private.pem')
  },
  ES256: {
    invalidPrivateKey: loadKey('priv.pem')
  }
};

if (PS_SUPPORTED) {
  algorithmParams.PS256 = {
    invalidPrivateKey: loadKey('secp384r1-private.pem')
  };
}

describe('Asymmetric key validation', function() {
  Object.keys(algorithmParams).forEach(function(algorithm) {
    describe(algorithm, function() {
      const keys = algorithmParams[algorithm];

      describe('when validating a key with an invalid private key type', function () {
        it('should throw an error', function () {
          const expectedErrorMessage = /"alg" parameter for "[\w\d-]+" key type must be one of:/;

          expect(function() {
            validateAsymmetricKey(algorithm, keys.invalidPrivateKey);
          }).to.throw(expectedErrorMessage);
        });
      });
    });
  });

  describe('when the function has missing parameters', function() {
    it('should pass the validation if no key has been provided', function() {
      const algorithm = 'ES256';
      validateAsymmetricKey(algorithm);
    });

    it('should pass the validation if no algorithm has been provided', function() {
      const key = loadKey('dsa-private.pem');
      validateAsymmetricKey(null, key);
    });
  });

  describe('when validating a key with an unsupported type', function () {
    it('should throw an error', function() {
      const algorithm = 'RS256';
      const key = loadKey('dsa-private.pem');
      const expectedErrorMessage = 'Unknown key type "dsa".';

      expect(function() {
        validateAsymmetricKey(algorithm, key);
      }).to.throw(expectedErrorMessage);
    });
  });

  describe('Elliptic curve algorithms', function () {
    const curvesAlgorithms = [
      { algorithm: 'ES256', curve: 'prime256v1' },
      { algorithm: 'ES384', curve: 'secp384r1' },
      { algorithm: 'ES512', curve: 'secp521r1' },
    ];

    const curvesKeys = [
      { curve: 'prime256v1', key: loadKey('prime256v1-private.pem') },
      { curve: 'secp384r1', key: loadKey('secp384r1-private.pem') },
      { curve: 'secp521r1', key: loadKey('secp521r1-private.pem') }
    ];

    describe('when validating keys generated using Elliptic Curves', function () {
      curvesAlgorithms.forEach(function(curveAlgorithm) {
        curvesKeys
          .forEach((curveKeys) => {
            if (curveKeys.curve !== curveAlgorithm.curve) {
              if (ASYMMETRIC_KEY_DETAILS_SUPPORTED) {
                it(`should throw an error when validating an ${curveAlgorithm.algorithm} token for key with curve ${curveKeys.curve}`, function() {
                  expect(() => {
                    validateAsymmetricKey(curveAlgorithm.algorithm, curveKeys.key);
                  }).to.throw(`"alg" parameter "${curveAlgorithm.algorithm}" requires curve "${curveAlgorithm.curve}".`);
                });
              } else {
                it(`should pass the validation for incorrect keys if the Node version does not support checking the key's curve name`, function() {
                  expect(() => {
                    validateAsymmetricKey(curveAlgorithm.algorithm, curveKeys.key);
                  }).not.to.throw();
                });
              }
            } else {
              it(`should accept an ${curveAlgorithm.algorithm} token for key with curve ${curveKeys.curve}`, function() {
                expect(() => {
                  validateAsymmetricKey(curveAlgorithm.algorithm, curveKeys.key);
                }).not.to.throw();
              });
            }
          });
      });
    });
  });

  if (RSA_PSS_KEY_DETAILS_SUPPORTED) {
    describe('RSA-PSS algorithms', function () {
      const key = loadKey('rsa-pss-private.pem');

      it(`it should throw an error when validating a key with wrong RSA-RSS parameters`, function () {
        const algorithm = 'PS512';
        expect(function() {
          validateAsymmetricKey(algorithm, key);
        }).to.throw('Invalid key for this operation, its RSA-PSS parameters do not meet the requirements of "alg" PS512')
      });

      it(`it should throw an error when validating a key with invalid salt length`, function () {
        const algorithm = 'PS256';
        const shortSaltKey = loadKey('rsa-pss-invalid-salt-length-private.pem');
        expect(function() {
          validateAsymmetricKey(algorithm, shortSaltKey);
        }).to.throw('Invalid key for this operation, its RSA-PSS parameter saltLength does not meet the requirements of "alg" PS256.')
      });

      it(`it should pass the validation when the key matches all the requirements for the algorithm`, function () {
        expect(function() {
          const algorithm = 'PS256';
          validateAsymmetricKey(algorithm, key);
        }).not.to.throw()
      });
    });
  }
});
