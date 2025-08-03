import { JsonWebTokenError } from '../JsonWebTokenError.js';
import { NotBeforeError } from '../NotBeforeError.js';
import { TokenExpiredError } from '../TokenExpiredError.js';
import { decode } from '../../decode.js';
import { timespan } from '../timespan.js';
import { validateAsymmetricKey } from '../validateAsymmetricKey.js';
import { getAlgorithm } from '../algorithms/index.js';
import { validateHeader } from './header-validation.js';
import { validateTokenSize, DEFAULT_MAX_TOKEN_SIZE } from './dos-protection.js';
import { validateAlgorithmKeyMatch } from './key-validation.js';
import { validateAndNormalizeKey } from './encoding-validation.js';
import { validateCryptographicParameters, validateSignatureFormat } from './crypto-validation.js';
import { KeyObject, createSecretKey, createPublicKey } from 'crypto';
import {
  Algorithm,
  VerifyOptions,
  PublicKey,
  Secret,
  JwtPayload,
  CompleteResult,
  JwtHeader
} from '../../types.js';

// Modern algorithm categories
export const PUB_KEY_ALGS: Algorithm[] = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512', 'ES256K', 'EdDSA'];
export const EC_KEY_ALGS: Algorithm[] = ['ES256', 'ES384', 'ES512', 'ES256K'];
export const RSA_KEY_ALGS: Algorithm[] = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512'];
export const HS_ALGS: Algorithm[] = ['HS256', 'HS384', 'HS512'];
export const NONE_ALGS: Algorithm[] = ['none'];

// Timestamp validation constants
export const MIN_TIMESTAMP = 0;
export const MAX_TIMESTAMP = Number.MAX_SAFE_INTEGER;
export const MAX_CLOCK_TOLERANCE = 157680000; // 5 years in seconds

export interface VerifyContext {
  jwtString: string;
  secretOrPublicKey: Secret | PublicKey;
  options: VerifyOptions;
  decodedToken: CompleteResult;
  header: JwtHeader;
  payload: JwtPayload;
}

export function validateOptions(options: VerifyOptions): void {
  if (options.clockTimestamp && typeof options.clockTimestamp !== 'number') {
    throw new JsonWebTokenError('clockTimestamp must be a number');
  }
  
  if (options.clockTimestamp !== undefined && typeof options.clockTimestamp === 'number') {
    validateTimestamp(options.clockTimestamp, 'clockTimestamp');
  }
  
  // Validate clockTolerance in options
  validateClockTolerance(options.clockTolerance);

  if (options.nonce !== undefined && (typeof options.nonce !== 'string' || options.nonce.trim() === '')) {
    throw new JsonWebTokenError('nonce must be a non-empty string');
  }

  if (options.allowInvalidAsymmetricKeyTypes !== undefined && typeof options.allowInvalidAsymmetricKeyTypes !== 'boolean') {
    throw new JsonWebTokenError('allowInvalidAsymmetricKeyTypes must be a boolean');
  }
}

export function prepareVerifyContext(
  jwtString: string,
  secretOrPublicKey: Secret | PublicKey,
  options: VerifyOptions = {}
): VerifyContext {
  // Clone this object since we are going to mutate it.
  options = { ...options };

  validateOptions(options);

  if (!jwtString) {
    throw new JsonWebTokenError('jwt must be provided');
  }

  if (typeof jwtString !== 'string') {
    throw new JsonWebTokenError('jwt must be a string');
  }

  // Apply DoS protection - validate token size
  if (!options.disableDoSProtection) {
    const maxTokenSize = options.maxTokenSize ?? DEFAULT_MAX_TOKEN_SIZE;
    validateTokenSize(jwtString, maxTokenSize);
  }

  const parts = jwtString.split('.');

  if (parts.length !== 3) {
    throw new JsonWebTokenError('jwt malformed');
  }

  let decodedToken: CompleteResult | null;

  try {
    decodedToken = decode(jwtString, { 
      complete: true,
      // Pass DoS options to decode
      maxTokenSize: options.maxTokenSize,
      maxPayloadSize: options.maxPayloadSize,
      maxPayloadDepth: options.maxPayloadDepth,
      maxClaimCount: options.maxClaimCount,
      disableDoSProtection: options.disableDoSProtection
    });
  } catch (err) {
    throw err as JsonWebTokenError;
  }

  if (!decodedToken) {
    throw new JsonWebTokenError('invalid token');
  }

  const header = decodedToken.header;
  
  // Validate that payload is an object (not a string from failed JSON parsing)
  if (typeof decodedToken.payload !== 'object' || decodedToken.payload === null) {
    throw new JsonWebTokenError('invalid token');
  }
  
  // Validate header for security issues
  validateHeader(header, options);

  return {
    jwtString,
    secretOrPublicKey,
    options,
    decodedToken,
    header,
    payload: decodedToken.payload
  };
}

export function prepareKey(key: Secret | PublicKey, header: JwtHeader): string | Buffer | KeyObject {
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
    // Normalize the key for consistent Unicode representation
    const normalizedKey = validateAndNormalizeKey(key, 'Secret key');
    return createSecretKey(Buffer.from(normalizedKey));
  }

  return key;
}

export function determineAlgorithms(options: VerifyOptions, header: JwtHeader, key: Secret | PublicKey | null): Algorithm[] {
  if (!options.algorithms) {
    if (header.alg === 'none') {
      return NONE_ALGS;
    } else if (key != null) {
      // Check if it's an asymmetric algorithm in the header
      if (PUB_KEY_ALGS.includes(header.alg as Algorithm)) {
        // For asymmetric algorithms, algorithms option is required
        throw new JsonWebTokenError('please pass "algorithms" option');
      }
      
      // Check if key is a KeyObject
      if (key instanceof KeyObject) {
        const keyType = key.asymmetricKeyType;
        if (!keyType) {
          // Symmetric key (secret)
          return HS_ALGS;
        } else if (keyType === 'ec') {
          return EC_KEY_ALGS;
        } else if (keyType === 'rsa' || keyType === 'rsa-pss') {
          return RSA_KEY_ALGS;
        } else if (['ed25519', 'ed448', 'x25519', 'x448'].includes(keyType)) {
          return ['EdDSA'];
        } else {
          return HS_ALGS;
        }
      } else {
        // String or Buffer - treat as HMAC secret
        return HS_ALGS;
      }
    } else {
      throw new JsonWebTokenError('secretOrPublicKey must have a value');
    }
  }
  
  return options.algorithms;
}

export function verifySignature(
  context: VerifyContext,
  key: Secret | PublicKey
): void {
  const { jwtString, header, options } = context;
  const parts = jwtString.split('.');
  const hasSignature = parts[2].trim() !== '';

  // Handle 'none' algorithm verification
  if (header.alg === 'none') {
    // Security warning for 'none' algorithm
    console.warn('WARNING: Verifying JWT with "none" algorithm - this token has NO security!');
    
    if (hasSignature) {
      throw new JsonWebTokenError('jwt signature must be empty for "none" algorithm');
    }
    
    // Security check: explicitly specifying 'none' in algorithms is not allowed
    if (options.algorithms && options.algorithms.includes('none')) {
      throw new JsonWebTokenError('Invalid verify option "algorithms" for "none" algorithm');
    }
    
    // For 'none' algorithm, we don't need a key, but if one is provided with none in algorithms, that's suspicious
    if (options.algorithms && options.algorithms.indexOf('none') === -1) {
      throw new JsonWebTokenError('invalid algorithm');
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

  const algorithms = determineAlgorithms(options, header, key);

  if (algorithms!.indexOf(header.alg as Algorithm) === -1) {
    throw new JsonWebTokenError('invalid algorithm');
  }

  // Skip signature verification for 'none' algorithm
  if (header.alg !== 'none') {
    let valid: boolean;

    try {
      const secretOrKey = prepareKey(key!, header);
      
      // Validate algorithm/key match to prevent key confusion attacks
      validateAlgorithmKeyMatch(header.alg, secretOrKey);
      
      // Validate RSA key size for verification
      if (secretOrKey instanceof KeyObject && !options.allowInsecureKeySizes) {
        const keyType = secretOrKey.asymmetricKeyType;
        if ((keyType === 'rsa' || keyType === 'rsa-pss') && (secretOrKey as any).asymmetricKeyDetails?.modulusLength < 2048) {
          throw new Error('minimum RSA key size is 2048 bits');
        }
      }
      
      // Extract the message (header.payload) and signature
      const lastDotIndex = jwtString.lastIndexOf('.');
      const message = jwtString.substring(0, lastDotIndex);
      const signature = jwtString.substring(lastDotIndex + 1);
      
      // Validate signature format
      validateSignatureFormat(signature, header.alg);
      
      // Validate cryptographic parameters (key and signature)
      if (secretOrKey instanceof KeyObject) {
        validateCryptographicParameters(secretOrKey, header.alg, signature);
      }
      
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
}

function validateTimestamp(value: number, name: string): void {
  if (value < MIN_TIMESTAMP || value > MAX_TIMESTAMP) {
    throw new JsonWebTokenError(
      `${name} timestamp must be between 0 and ${MAX_TIMESTAMP} (actual: ${value})`
    );
  }
}

function validateClockTolerance(tolerance?: number): void {
  if (tolerance !== undefined) {
    if (typeof tolerance !== 'number' || isNaN(tolerance)) {
      throw new JsonWebTokenError('clockTolerance must be a number');
    }
    if (tolerance < 0) {
      throw new JsonWebTokenError('clockTolerance must not be negative');
    }
    if (tolerance > MAX_CLOCK_TOLERANCE) {
      throw new JsonWebTokenError(
        `clockTolerance must not exceed ${MAX_CLOCK_TOLERANCE} seconds (5 years)`
      );
    }
  }
}

export function validateClaims(
  payload: JwtPayload,
  options: VerifyOptions,
  clockTimestamp: number
): void {
  // Validate clockTimestamp
  validateTimestamp(clockTimestamp, 'clockTimestamp');
  
  // Validate clockTolerance
  validateClockTolerance(options.clockTolerance);
  
  if (typeof payload.nbf !== 'undefined' && !options.ignoreNotBefore) {
    if (typeof payload.nbf !== 'number') {
      throw new JsonWebTokenError('invalid nbf value');
    }
    validateTimestamp(payload.nbf, 'nbf');
    if (payload.nbf > clockTimestamp + (options.clockTolerance || 0)) {
      throw new NotBeforeError('jwt not active', new Date(payload.nbf * 1000));
    }
  }

  if (typeof payload.exp !== 'undefined' && !options.ignoreExpiration) {
    if (typeof payload.exp !== 'number') {
      throw new JsonWebTokenError('invalid exp value');
    }
    validateTimestamp(payload.exp, 'exp');
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
    validateTimestamp(payload.iat, 'iat');

    const maxAgeTimestamp = timespan(options.maxAge, payload.iat);
    if (typeof maxAgeTimestamp === 'undefined' || isNaN(maxAgeTimestamp)) {
      throw new JsonWebTokenError('"maxAge" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60');
    }
    validateTimestamp(maxAgeTimestamp, 'maxAgeTimestamp');
    if (clockTimestamp > maxAgeTimestamp + (options.clockTolerance || 0)) {
      throw new TokenExpiredError('maxAge exceeded', new Date(maxAgeTimestamp * 1000));
    }
  }
  
  // Also validate iat if present, even without maxAge
  if (typeof payload.iat !== 'undefined' && typeof payload.iat === 'number') {
    validateTimestamp(payload.iat, 'iat');
  }
}