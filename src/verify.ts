import { JsonWebTokenError } from './lib/JsonWebTokenError.js';
import { NotBeforeError } from './lib/NotBeforeError.js';
import { TokenExpiredError } from './lib/TokenExpiredError.js';
import { decode } from './decode.js';
import { timespan } from './lib/timespan.js';
import { validateAsymmetricKey } from './lib/validateAsymmetricKey.js';
import { getAlgorithm } from './lib/algorithms/index.js';
import { KeyObject, createSecretKey, createPublicKey } from 'crypto';
import {
  Algorithm,
  VerifyOptions,
  PublicKey,
  Secret,
  GetPublicKeyOrSecret,
  JwtPayload,
  CompleteResult,
  JwtHeader,
  VerifyErrors
} from './types.js';

// Modern algorithm categories
const PUB_KEY_ALGS: Algorithm[] = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512', 'ES256K', 'EdDSA'];
const EC_KEY_ALGS: Algorithm[] = ['ES256', 'ES384', 'ES512', 'ES256K'];
const RSA_KEY_ALGS: Algorithm[] = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512'];
const HS_ALGS: Algorithm[] = ['HS256', 'HS384', 'HS512'];
const NONE_ALGS: Algorithm[] = ['none'];

// Overloaded function signatures
export async function verify(token: string, secretOrPublicKey: Secret | PublicKey | GetPublicKeyOrSecret, options: VerifyOptions & { complete: true }): Promise<CompleteResult>;
export async function verify(token: string, secretOrPublicKey: Secret | PublicKey | GetPublicKeyOrSecret, options?: VerifyOptions): Promise<JwtPayload>;

export async function verify(
  jwtString: string,
  secretOrPublicKey: Secret | PublicKey | GetPublicKeyOrSecret,
  options: VerifyOptions = {}
): Promise<JwtPayload | CompleteResult> {
  // Clone this object since we are going to mutate it.
  options = { ...options };


  if (options.clockTimestamp && typeof options.clockTimestamp !== 'number') {
    throw new JsonWebTokenError('clockTimestamp must be a number');
  }

  if (options.nonce !== undefined && (typeof options.nonce !== 'string' || options.nonce.trim() === '')) {
    throw new JsonWebTokenError('nonce must be a non-empty string');
  }

  if (options.allowInvalidAsymmetricKeyTypes !== undefined && typeof options.allowInvalidAsymmetricKeyTypes !== 'boolean') {
    throw new JsonWebTokenError('allowInvalidAsymmetricKeyTypes must be a boolean');
  }

  const clockTimestamp = options.clockTimestamp || Math.floor(Date.now() / 1000);

  if (!jwtString) {
    throw new JsonWebTokenError('jwt must be provided');
  }

  if (typeof jwtString !== 'string') {
    throw new JsonWebTokenError('jwt must be a string');
  }

  const parts = jwtString.split('.');

  if (parts.length !== 3) {
    throw new JsonWebTokenError('jwt malformed');
  }

  let decodedToken: CompleteResult | null;

  try {
    decodedToken = decode(jwtString, { complete: true });
  } catch (err) {
    throw err as JsonWebTokenError;
  }

  if (!decodedToken) {
    throw new JsonWebTokenError('invalid token');
  }

  const header = decodedToken.header;
  
  // Handle async key resolution
  let key: Secret | PublicKey;
  if (typeof secretOrPublicKey === 'function') {
    key = await secretOrPublicKey(header);
  } else {
    key = secretOrPublicKey;
  }

    const hasSignature = parts[2].trim() !== '';

  // Handle 'none' algorithm verification
  if (header.alg === 'none') {
    // Security warning for 'none' algorithm
    console.warn('WARNING: Verifying JWT with "none" algorithm - this token has NO security!');
    
    if (hasSignature) {
      throw new JsonWebTokenError('jwt signature must be empty for "none" algorithm');
    }
    
    // For 'none' algorithm, we don't need a key, but if one is provided with none in algorithms, that's suspicious
    if (options.algorithms && options.algorithms.indexOf('none') === -1) {
      throw new JsonWebTokenError('invalid algorithm');
    }
    
    // Security check: if a key is provided but 'none' is in algorithms, this is likely an attack
    if (key && options.algorithms && options.algorithms.includes('none')) {
      throw new JsonWebTokenError('key should not be provided when verifying unsigned tokens');
    }
  } else {
    // For all other algorithms, standard checks apply
    if (!hasSignature && key) {
      throw new JsonWebTokenError('jwt signature is required');
    }

    if (!key && hasSignature) {
      throw new JsonWebTokenError('secretOrPublicKey must have a value');
    }
  }

  if (!options.algorithms) {
    if (header.alg === 'none') {
      options.algorithms = NONE_ALGS;
    } else if (key != null) {
      const keyType = (key as KeyObject).asymmetricKeyType;
      if (!keyType || keyType === 'ec') {
        options.algorithms = EC_KEY_ALGS;
      } else if (keyType === 'rsa' || keyType === 'rsa-pss') {
        options.algorithms = RSA_KEY_ALGS;
      } else if (['ed25519', 'ed448', 'x25519', 'x448'].includes(keyType)) {
        options.algorithms = ['EdDSA'];
      } else {
        options.algorithms = HS_ALGS;
      }
    } else {
      throw new JsonWebTokenError('secretOrPublicKey must have a value');
    }
  }

  if (options.algorithms!.indexOf(header.alg as Algorithm) === -1) {
    throw new JsonWebTokenError('invalid algorithm');
  }

  // Skip signature verification for 'none' algorithm
  if (header.alg !== 'none') {
    let valid: boolean;

    try {
      const secretOrKey = prepareKey(key!);
      
      // Extract the message (header.payload) and signature
      const lastDotIndex = jwtString.lastIndexOf('.');
      const message = jwtString.substring(0, lastDotIndex);
      const signature = jwtString.substring(lastDotIndex + 1);
      
      // Get the algorithm implementation and verify
      const algorithm = getAlgorithm(header.alg);
      valid = algorithm.verify(message, signature, secretOrKey);
    } catch (e: any) {
      throw e;
    }

    if (!valid) {
      throw new JsonWebTokenError('invalid signature');
    }
  }

  const payload = decodedToken.payload;

  if (typeof payload.nbf !== 'undefined' && !options.ignoreNotBefore) {
    if (typeof payload.nbf !== 'number') {
      throw new JsonWebTokenError('invalid nbf value');
    }
    if (payload.nbf > clockTimestamp + (options.clockTolerance || 0)) {
      throw new NotBeforeError('jwt not active', new Date(payload.nbf * 1000));
    }
  }

  if (typeof payload.exp !== 'undefined' && !options.ignoreExpiration) {
    if (typeof payload.exp !== 'number') {
      throw new JsonWebTokenError('invalid exp value');
    }
    if (clockTimestamp >= payload.exp + (options.clockTolerance || 0)) {
      throw new TokenExpiredError('jwt expired', new Date(payload.exp * 1000));
    }
  }

  if (options.audience) {
    const audiences = Array.isArray(options.audience) ? options.audience : [options.audience];
    const target = Array.isArray(payload.aud) ? payload.aud : [payload.aud];

    const match = target.some(function(targetAudience) {
      return audiences.some(function(audience) {
        return audience instanceof RegExp ? audience.test(targetAudience || '') : audience === targetAudience;
      });
    });

    if (!match) {
      throw new JsonWebTokenError('jwt audience invalid. expected: ' + audiences.join(' or '));
    }
  }

  if (options.issuer) {
    const invalid_issuer = 
      (typeof options.issuer === 'string' && payload.iss !== options.issuer) ||
      (Array.isArray(options.issuer) && options.issuer.indexOf(payload.iss || '') === -1);
      
    if (invalid_issuer) {
      throw new JsonWebTokenError('jwt issuer invalid. expected: ' + options.issuer);
    }
  }

  if (options.subject) {
    if (payload.sub !== options.subject) {
      throw new JsonWebTokenError('jwt subject invalid. expected: ' + options.subject);
    }
  }

  if (options.jwtid) {
    if (payload.jti !== options.jwtid) {
      throw new JsonWebTokenError('jwt jwtid invalid. expected: ' + options.jwtid);
    }
  }

  if (options.nonce) {
    if (payload.nonce !== options.nonce) {
      throw new JsonWebTokenError('jwt nonce invalid. expected: ' + options.nonce);
    }
  }

  if (options.maxAge) {
    if (typeof payload.iat !== 'number') {
      throw new JsonWebTokenError('iat required when maxAge is specified');
    }

    const maxAgeTimestamp = timespan(options.maxAge, payload.iat);
    if (typeof maxAgeTimestamp === 'undefined' || isNaN(maxAgeTimestamp)) {
      throw new JsonWebTokenError('"maxAge" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60');
    }
    if (clockTimestamp >= maxAgeTimestamp + (options.clockTolerance || 0)) {
      throw new TokenExpiredError('maxAge exceeded', new Date(maxAgeTimestamp * 1000));
    }
  }

  if (options.complete === true) {
    const signature = decodedToken.signature;

    return {
      header: header,
      payload: payload,
      signature: signature
    };
  }

  return payload;

  function prepareKey(key: Secret | PublicKey): string | Buffer | KeyObject {
    if (key instanceof KeyObject) {
      return key;
    }

    if (typeof key === 'object' && !(key instanceof Buffer)) {
      if (!('key' in key) || typeof key.key !== 'string' || !key.key.trim()) {
        throw new JsonWebTokenError('secretOrPublicKey.key must have a value');
      }
      
      return createPublicKey(key);
    }

    if (Buffer.isBuffer(key)) {
      return createSecretKey(key);
    }

    if (typeof key === 'string' && PUB_KEY_ALGS.includes(header.alg as Algorithm)) {
      return createPublicKey(key);
    }

    if (typeof key === 'string' && HS_ALGS.includes(header.alg as Algorithm)) {
      return createSecretKey(Buffer.from(key));
    }

    return key;
  }
}