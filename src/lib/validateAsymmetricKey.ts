import { KeyObject } from 'crypto';
import { Algorithm } from '../types.js';
import { ASYMMETRIC_KEY_DETAILS_SUPPORTED } from './asymmetricKeyDetailsSupported.js';
import { RSA_PSS_KEY_DETAILS_SUPPORTED } from './rsaPssKeyDetailsSupported.js';
import { validateCryptographicParameters } from './shared/crypto-validation.js';

type AsymmetricKeyType = 'ec' | 'rsa' | 'rsa-pss' | 'ed25519' | 'ed448' | 'x25519' | 'x448';

const allowedAlgorithmsForKeys: Record<AsymmetricKeyType, Algorithm[]> = {
  'ec': ['ES256', 'ES384', 'ES512', 'ES256K'],
  'rsa': ['RS256', 'PS256', 'RS384', 'PS384', 'RS512', 'PS512'],
  'rsa-pss': ['PS256', 'PS384', 'PS512'],
  'ed25519': ['EdDSA'],
  'ed448': ['EdDSA'],
  'x25519': ['EdDSA'],
  'x448': ['EdDSA']
};

const allowedCurves: Record<string, string> = {
  ES256: 'prime256v1',
  ES384: 'secp384r1',
  ES512: 'secp521r1',
  ES256K: 'secp256k1'
};

export function validateAsymmetricKey(algorithm: Algorithm | undefined, key: KeyObject | undefined, allowInsecureKeySizes = false): void {
  if (!algorithm || !key) return;

  const keyType = key.asymmetricKeyType as AsymmetricKeyType | undefined;
  if (!keyType) return;

  const allowedAlgorithms = allowedAlgorithmsForKeys[keyType];

  if (!allowedAlgorithms) {
    throw new Error(`Unknown key type "${keyType}".`);
  }

  if (!allowedAlgorithms.includes(algorithm)) {
    throw new Error(`"alg" parameter for "${keyType}" key type must be one of: ${allowedAlgorithms.join(', ')}.`);
  }
  
  // Check RSA key size
  if ((keyType === 'rsa' || keyType === 'rsa-pss') && !allowInsecureKeySizes && ASYMMETRIC_KEY_DETAILS_SUPPORTED) {
    const keySize = (key as any).asymmetricKeyDetails?.modulusLength;
    if (keySize && keySize < 2048) {
      throw new Error(`minimum RSA key size is 2048 bits`);
    }
  }

  /*
   * Ignore the next block from test coverage because it gets executed
   * conditionally depending on the Node version. Not ignoring it would
   * prevent us from reaching the target % of coverage for versions of
   * Node under 15.7.0.
   */
  /* istanbul ignore next */
  if (ASYMMETRIC_KEY_DETAILS_SUPPORTED) {
    switch (keyType) {
      case 'ec': {
        const keyCurve = (key as any).asymmetricKeyDetails?.namedCurve;
        const allowedCurve = allowedCurves[algorithm];

        if (keyCurve !== allowedCurve) {
          throw new Error(`"alg" parameter "${algorithm}" requires curve "${allowedCurve}".`);
        }
        break;
      }

      case 'rsa-pss': {
        if (RSA_PSS_KEY_DETAILS_SUPPORTED) {
          const length = parseInt(algorithm.slice(-3), 10);
          const keyDetails = (key as any).asymmetricKeyDetails;
          const { hashAlgorithm, mgf1HashAlgorithm, saltLength } = keyDetails || {};

          if (hashAlgorithm !== `sha${length}` || mgf1HashAlgorithm !== hashAlgorithm) {
            throw new Error(`Invalid key for this operation, its RSA-PSS parameters do not meet the requirements of "alg" ${algorithm}.`);
          }

          if (saltLength !== undefined && saltLength > length >> 3) {
            throw new Error(`Invalid key for this operation, its RSA-PSS parameter saltLength does not meet the requirements of "alg" ${algorithm}.`);
          }
        }
        break;
      }
    }
  }
  
  // Perform additional cryptographic parameter validation
  validateCryptographicParameters(key, algorithm);
}