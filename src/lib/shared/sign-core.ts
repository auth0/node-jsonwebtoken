import { timespan } from '../timespan.js';
import { validateAsymmetricKey } from '../validateAsymmetricKey.js';
import { createSecuredInput, base64urlEncode } from '../jwt-core.js';
import { getAlgorithm } from '../algorithms/index.js';
import { safeObjectAssign } from './prototype-pollution-protection.js';
import { validatePayloadDepth, validateClaimCount, validateTokenSize, validatePayloadSize, DEFAULT_MAX_PAYLOAD_DEPTH, DEFAULT_MAX_CLAIM_COUNT, DEFAULT_MAX_TOKEN_SIZE, DEFAULT_MAX_PAYLOAD_SIZE } from './dos-protection.js';
import { validateAlgorithmKeyMatch } from './key-validation.js';
import { validatePayloadString } from './encoding-validation.js';
import { KeyObject, createSecretKey, createPrivateKey } from 'crypto';
import { JsonWebTokenError } from '../JsonWebTokenError.js';
import { 
  Algorithm, 
  SignOptions, 
  Secret, 
  JwtPayload,
  JwtHeader 
} from '../../types.js';

// Timestamp validation constants (must match verify-core.ts)
const MIN_TIMESTAMP = 0;
const MAX_TIMESTAMP = Number.MAX_SAFE_INTEGER;

function validateSignTimestamp(value: number, name: string): void {
  if (value < MIN_TIMESTAMP || value > MAX_TIMESTAMP) {
    throw new JsonWebTokenError(
      `${name} timestamp must be between 0 and ${MAX_TIMESTAMP} (actual: ${value})`
    );
  }
}

// Helper function for plain object check (no built-in equivalent)
const isPlainObject = (value: any): value is Record<string, any> => 
  value !== null && typeof value === 'object' && value.constructor === Object;

// Modern algorithm support including EdDSA
export const SUPPORTED_ALGS: Algorithm[] = [
  'RS256', 'RS384', 'RS512',
  'PS256', 'PS384', 'PS512',
  'ES256', 'ES384', 'ES512', 'ES256K',
  'EdDSA',
  'HS256', 'HS384', 'HS512',
  'none'
];

interface SignOptionsSchema {
  [key: string]: {
    isValid: (value: any) => boolean;
    message: string;
  };
}

export const sign_options_schema: SignOptionsSchema = {
  expiresIn: { isValid(value) { return Number.isInteger(value) || (typeof value === 'string' && !!value); }, message: '"expiresIn" should be a number of seconds or string representing a timespan' },
  notBefore: { isValid(value) { return Number.isInteger(value) || (typeof value === 'string' && !!value); }, message: '"notBefore" should be a number of seconds or string representing a timespan' },
  audience: { isValid(value) { return typeof value === 'string' || Array.isArray(value); }, message: '"audience" must be a string or array' },
  algorithm: { isValid: (value) => SUPPORTED_ALGS.includes(value), message: '"algorithm" must be a valid string enum value' },
  header: { isValid: isPlainObject, message: '"header" must be an object' },
  encoding: { isValid: (value) => typeof value === 'string', message: '"encoding" must be a string' },
  issuer: { isValid: (value) => typeof value === 'string', message: '"issuer" must be a string' },
  subject: { isValid: (value) => typeof value === 'string', message: '"subject" must be a string' },
  jwtid: { isValid: (value) => typeof value === 'string', message: '"jwtid" must be a string' },
  noTimestamp: { isValid: (value) => typeof value === 'boolean', message: '"noTimestamp" must be a boolean' },
  keyid: { isValid: (value) => typeof value === 'string', message: '"keyid" must be a string' },
  mutatePayload: { isValid: (value) => typeof value === 'boolean', message: '"mutatePayload" must be a boolean' },
  allowInsecureKeySizes: { isValid: (value) => typeof value === 'boolean', message: '"allowInsecureKeySizes" must be a boolean'},
  allowInvalidAsymmetricKeyTypes: { isValid: (value) => typeof value === 'boolean', message: '"allowInvalidAsymmetricKeyTypes" must be a boolean'},
  allowInsecureNoneAlgorithm: { isValid: (value) => typeof value === 'boolean', message: '"allowInsecureNoneAlgorithm" must be a boolean'},
  // DoS protection options
  maxTokenSize: { isValid: (value) => typeof value === 'number' && value > 0, message: '"maxTokenSize" must be a positive number' },
  maxPayloadSize: { isValid: (value) => typeof value === 'number' && value > 0, message: '"maxPayloadSize" must be a positive number' },
  maxPayloadDepth: { isValid: (value) => typeof value === 'number' && value > 0, message: '"maxPayloadDepth" must be a positive number' },
  maxClaimCount: { isValid: (value) => typeof value === 'number' && value > 0, message: '"maxClaimCount" must be a positive number' },
  disableDoSProtection: { isValid: (value) => typeof value === 'boolean', message: '"disableDoSProtection" must be a boolean' }
};

export const registered_claims_schema: SignOptionsSchema = {
  iat: { 
    isValid: (value) => Number.isFinite(value) && value >= MIN_TIMESTAMP && value <= MAX_TIMESTAMP,
    message: `"iat" should be a number of seconds between 0 and ${MAX_TIMESTAMP}`
  },
  exp: { 
    isValid: (value) => Number.isFinite(value) && value >= MIN_TIMESTAMP && value <= MAX_TIMESTAMP,
    message: `"exp" should be a number of seconds between 0 and ${MAX_TIMESTAMP}`
  },
  nbf: { 
    isValid: (value) => Number.isFinite(value) && value >= MIN_TIMESTAMP && value <= MAX_TIMESTAMP,
    message: `"nbf" should be a number of seconds between 0 and ${MAX_TIMESTAMP}`
  }
};

export function validate(schema: SignOptionsSchema, allowUnknown: boolean, object: any, parameterName: string): void {
  if (!isPlainObject(object)) {
    throw new Error(`Expected "${parameterName}" to be a plain object.`);
  }
  Object.keys(object).forEach((key) => {
    const validator = schema[key];
    if (!validator) {
      if (!allowUnknown) {
        throw new Error(`"${key}" is not allowed in "${parameterName}"`);
      }
      return;
    }
    if (!validator.isValid(object[key])) {
      throw new Error(validator.message);
    }
  });
}

export function validateOptions(options: any): void {
  return validate(sign_options_schema, false, options, 'options');
}

export function validatePayload(payload: any): void {
  return validate(registered_claims_schema, true, payload, 'payload');
}

export const options_to_payload: Record<string, string> = {
  'audience': 'aud',
  'issuer': 'iss',
  'subject': 'sub',
  'jwtid': 'jti'
};

export const options_for_objects = [
  'expiresIn',
  'notBefore',
  'noTimestamp',
  'audience',
  'issuer',
  'subject',
  'jwtid',
];

export interface SignContext {
  payload: string | Buffer | object;
  secretOrPrivateKey: Secret;
  options: SignOptions;
  isObjectPayload: boolean;
  header: JwtHeader;
}

export function prepareSignContext(
  payload: string | Buffer | object,
  secretOrPrivateKey: Secret,
  options: SignOptions = {}
): SignContext {
  const isObjectPayload = typeof payload === 'object' &&
                        !Buffer.isBuffer(payload);

  const header: JwtHeader = {
    alg: (options.algorithm || 'HS256') as Algorithm,
    typ: isObjectPayload ? 'JWT' : undefined,
    kid: options.keyid
  } as JwtHeader;

  if (options.header) {
    safeObjectAssign(header, options.header);
  }

  if (!secretOrPrivateKey && header.alg !== 'none') {
    throw new Error('secretOrPrivateKey must have a value');
  }
  
  // Security check for 'none' algorithm
  if (header.alg === 'none') {
    if (!options.allowInsecureNoneAlgorithm) {
      throw new Error('The "none" algorithm is insecure and disabled by default. To use it, you must explicitly set the allowInsecureNoneAlgorithm option to true. WARNING: Unsigned tokens provide NO security guarantees.');
    }
    // Log security warning when 'none' is used
    console.warn('WARNING: JWT signed with "none" algorithm - this token has NO security!');
  }

  if (typeof payload === 'undefined') {
    throw new Error('payload is required');
  } else if (isObjectPayload) {
    // Validate object payloads
    if (payload === null || Array.isArray(payload)) {
      throw new Error('Expected "payload" to be a plain object.');
    }
    validatePayload(payload);

    if (!options.mutatePayload) {
      payload = { ...payload as object };
    }
  } else {
    // For non-object payloads, only string and Buffer are allowed
    if (typeof payload !== 'string' && !Buffer.isBuffer(payload)) {
      throw new Error('Expected "payload" to be a plain object.');
    }
    
    // Validate string payloads for dangerous content
    if (typeof payload === 'string') {
      validatePayloadString(payload);
    }
    
    const invalid_options = options_for_objects.filter((opt) => 
      typeof (options as any)[opt] !== 'undefined'
    );

    if (invalid_options.length > 0) {
      const message = `invalid ${invalid_options.join(',')} option for ${typeof payload} payload`;
      throw new Error(message);
    }
  }

  if (typeof (payload as any).exp !== 'undefined' && typeof options.expiresIn !== 'undefined') {
    throw new Error('Bad "options.expiresIn" option the payload already has an "exp" property.');
  }

  if (typeof (payload as any).nbf !== 'undefined' && typeof options.notBefore !== 'undefined') {
    throw new Error('Bad "options.notBefore" option the payload already has an "nbf" property.');
  }

  validateOptions(options);

  // Apply DoS protection for object payloads during signing
  if (isObjectPayload && !options.disableDoSProtection) {
    const maxPayloadDepth = options.maxPayloadDepth ?? DEFAULT_MAX_PAYLOAD_DEPTH;
    const maxClaimCount = options.maxClaimCount ?? DEFAULT_MAX_CLAIM_COUNT;
    
    validatePayloadDepth(payload, maxPayloadDepth);
    validateClaimCount(payload, maxClaimCount);
  }

  return {
    payload,
    secretOrPrivateKey,
    options,
    isObjectPayload,
    header
  };
}

export function prepareSecret(secret: Secret, algorithm?: Algorithm): string | Buffer | KeyObject {
  if (!secret || (typeof secret === 'string' && !secret.trim())) {
    throw new Error('secretOrPrivateKey must have a value');
  }
  
  if (Buffer.isBuffer(secret) && secret.length === 0) {
    throw new Error('secretOrPrivateKey must have a value');
  }

  if (typeof secret === 'object' && !(secret instanceof Buffer) && !(secret instanceof KeyObject)) {
    if (!('key' in secret) || typeof secret.key !== 'string' || !secret.key.trim()) {
      throw new Error('secretOrPrivateKey.key must have a value');
    }
    
    secret = createPrivateKey(secret);
  }

  if (secret instanceof Buffer) {
    // For EdDSA and ES algorithms, treat buffer as private key
    if (algorithm === 'EdDSA' || algorithm?.startsWith('ES')) {
      return createPrivateKey(secret);
    }
    return createSecretKey(secret);
  }

  return secret;
}

export function validateKey(alg: Algorithm, key: string | Buffer | KeyObject, options: SignOptions) {
  if (alg.startsWith('ES') && key instanceof KeyObject) {
    if (key.asymmetricKeyType !== 'ec') {
      throw new Error('Invalid key for ECDSA algorithms');
    }
  }

  if (alg === 'EdDSA' && key instanceof KeyObject) {
    if (!['ed25519', 'ed448', 'x25519', 'x448'].includes(key.asymmetricKeyType!)) {
      throw new Error('Invalid key for EdDSA algorithm');
    }
  }

  if (key instanceof KeyObject && !options.allowInvalidAsymmetricKeyTypes) {
    try {
      validateAsymmetricKey(alg, key, options.allowInsecureKeySizes);
    } catch (error: any) {
      throw error;
    }
  }
}

export function createSignature(
  context: SignContext,
  timestamp?: number
): string {
  const { payload, secretOrPrivateKey, options, isObjectPayload, header } = context;
  let processedPayload = payload;
  
  if (timestamp && isObjectPayload) {
    // Validate the timestamp before using it
    validateSignTimestamp(timestamp, 'timestamp');
    
    if (!options.noTimestamp) {
      (processedPayload as any).iat = (processedPayload as any).iat || timestamp;
    }

    if (options.expiresIn !== undefined) {
      const expiresIn = timespan(options.expiresIn, (processedPayload as any).iat);
      
      if (typeof expiresIn === 'undefined' || isNaN(expiresIn)) {
        throw new Error('"expiresIn" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60');
      }
      validateSignTimestamp(expiresIn, 'exp');
      (processedPayload as any).exp = expiresIn;
    }

    if (options.notBefore !== undefined) {
      const notBefore = timespan(options.notBefore, (processedPayload as any).iat);
      
      if (typeof notBefore === 'undefined' || isNaN(notBefore)) {
        throw new Error('"notBefore" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60');
      }
      validateSignTimestamp(notBefore, 'nbf');
      (processedPayload as any).nbf = notBefore;
    }

    Object.keys(options_to_payload).forEach((key) => {
      const claim = options_to_payload[key];
      if (options[key as keyof SignOptions] !== undefined) {
        (processedPayload as any)[claim] = options[key as keyof SignOptions];
      }
    });
  }

  // Create the secured input (header.payload)
  const encoding = options.encoding as BufferEncoding || 'utf8';
  
  // If payload is an object, validate the stringified version for null bytes
  if (typeof processedPayload === 'object' && processedPayload !== null) {
    const payloadStr = JSON.stringify(processedPayload);
    validatePayloadString(payloadStr);
  }
  
  const securedInput = createSecuredInput(header, processedPayload, encoding);
  
  // Get the algorithm implementation and sign
  const algorithm = getAlgorithm(header.alg);
  const secretOrKey = header.alg === 'none' ? '' : prepareSecret(secretOrPrivateKey, options.algorithm);
  
  if (header.alg !== 'none') {
    validateKey(header.alg as Algorithm, secretOrKey, options);
    // Validate algorithm/key match to prevent key confusion attacks
    validateAlgorithmKeyMatch(header.alg, secretOrKey);
  }
  
  const signature = algorithm.sign(securedInput, secretOrKey);
  
  // Create the complete JWT
  const jwt = `${securedInput}.${signature}`;
  
  // Apply token size validation if DoS protection is enabled
  if (!options.disableDoSProtection) {
    const maxTokenSize = options.maxTokenSize ?? DEFAULT_MAX_TOKEN_SIZE;
    validateTokenSize(jwt, maxTokenSize);
    
    // Also validate payload size
    const payloadStr = typeof processedPayload === 'string' ? processedPayload : JSON.stringify(processedPayload);
    const maxPayloadSize = options.maxPayloadSize ?? DEFAULT_MAX_PAYLOAD_SIZE;
    validatePayloadSize(payloadStr, maxPayloadSize);
  }
  
  return jwt;
}