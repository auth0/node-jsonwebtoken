import { timespan } from './lib/timespan.js';
import { validateAsymmetricKey } from './lib/validateAsymmetricKey.js';
import { createSecuredInput, base64urlEncode } from './lib/jwt-core.js';
import { getAlgorithm } from './lib/algorithms/index.js';
import { KeyObject, createSecretKey, createPrivateKey } from 'crypto';
import { 
  Algorithm, 
  SignOptions, 
  Secret, 
  JwtPayload,
  JwtHeader 
} from './types.js';

// Helper function for plain object check (no built-in equivalent)
const isPlainObject = (value: any): value is Record<string, any> => 
  value !== null && typeof value === 'object' && value.constructor === Object;

// Modern algorithm support including EdDSA
const SUPPORTED_ALGS: Algorithm[] = [
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

const sign_options_schema: SignOptionsSchema = {
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
  allowInsecureNoneAlgorithm: { isValid: (value) => typeof value === 'boolean', message: '"allowInsecureNoneAlgorithm" must be a boolean'}
};

const registered_claims_schema: SignOptionsSchema = {
  iat: { isValid: Number.isFinite, message: '"iat" should be a number of seconds' },
  exp: { isValid: Number.isFinite, message: '"exp" should be a number of seconds' },
  nbf: { isValid: Number.isFinite, message: '"nbf" should be a number of seconds' }
};

function validate(schema: SignOptionsSchema, allowUnknown: boolean, object: any, parameterName: string): void {
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

function validateOptions(options: any): void {
  return validate(sign_options_schema, false, options, 'options');
}

function validatePayload(payload: any): void {
  return validate(registered_claims_schema, true, payload, 'payload');
}

const options_to_payload: Record<string, string> = {
  'audience': 'aud',
  'issuer': 'iss',
  'subject': 'sub',
  'jwtid': 'jti'
};

const options_for_objects = [
  'expiresIn',
  'notBefore',
  'noTimestamp',
  'audience',
  'issuer',
  'subject',
  'jwtid',
];

export async function sign(
  payload: string | Buffer | object,
  secretOrPrivateKey: Secret,
  options: SignOptions = {}
): Promise<string> {
  const opts = options;

  const isObjectPayload = typeof payload === 'object' &&
                        !Buffer.isBuffer(payload);

  const header: JwtHeader = {
    alg: (opts.algorithm || 'HS256') as Algorithm,
    typ: isObjectPayload ? 'JWT' : undefined,
    kid: opts.keyid
  } as JwtHeader;

  if (opts.header) {
    Object.assign(header, opts.header);
  }

  if (!secretOrPrivateKey && header.alg !== 'none') {
    throw new Error('secretOrPrivateKey must have a value');
  }
  
  // Security check for 'none' algorithm
  if (header.alg === 'none') {
    if (!opts.allowInsecureNoneAlgorithm) {
      throw new Error('The "none" algorithm is insecure and disabled by default. To use it, you must explicitly set the allowInsecureNoneAlgorithm option to true. WARNING: Unsigned tokens provide NO security guarantees.');
    }
    // Log security warning when 'none' is used
    console.warn('WARNING: JWT signed with "none" algorithm - this token has NO security!');
  }


  if (typeof payload === 'undefined') {
    throw new Error('payload is required');
  } else if (isObjectPayload) {
    validatePayload(payload);

    if (!opts.mutatePayload) {
      payload = { ...payload as object };
    }
  } else {
    const invalid_options = options_for_objects.filter((opt) => 
      typeof (opts as any)[opt] !== 'undefined'
    );

    if (invalid_options.length > 0) {
      const message = `invalid ${invalid_options.join(',')} option for ${typeof payload} payload`;
      throw new Error(message);
    }
  }

  if (typeof (payload as any).exp !== 'undefined' && typeof opts.expiresIn !== 'undefined') {
    throw new Error('Bad "options.expiresIn" option the payload already has an "exp" property.');
  }

  if (typeof (payload as any).nbf !== 'undefined' && typeof opts.notBefore !== 'undefined') {
    throw new Error('Bad "options.notBefore" option the payload already has an "nbf" property.');
  }

  validateOptions(opts);


  const timestamp = isObjectPayload ? Math.floor(Date.now() / 1000) : undefined;
  
  // For 'none' algorithm, skip secret preparation and validation
  if (header.alg === 'none') {
    return createSignature(payload, timestamp);
  }
  
  const secretOrKey = prepareSecret(secretOrPrivateKey);
  validateKey(header.alg as Algorithm, secretOrKey);
  return createSignature(payload, timestamp);

  function prepareSecret(secret: Secret): string | Buffer | KeyObject {
    if (!secret || (typeof secret === 'string' && !secret.trim())) {
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
      if (opts.algorithm === 'EdDSA' || opts.algorithm?.startsWith('ES')) {
        return createPrivateKey(secret);
      }
      return createSecretKey(secret);
    }

    return secret;
  }

  function validateKey(alg: Algorithm, key: string | Buffer | KeyObject) {
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

    if (key instanceof KeyObject && !opts.allowInvalidAsymmetricKeyTypes) {
      try {
        validateAsymmetricKey(alg, key);
      } catch (error: any) {
        throw error;
      }
    }
  }

  function createSignature(payload: any, timestamp?: number) {
    if (timestamp && isObjectPayload) {
      if (!opts.noTimestamp) {
        (payload as any).iat = (payload as any).iat || timestamp;
      }

      if (opts.expiresIn !== undefined) {
        const expiresIn = timespan(opts.expiresIn, (payload as any).iat);
        
        if (typeof expiresIn === 'undefined' || isNaN(expiresIn)) {
          throw new Error('"expiresIn" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60');
        }
        (payload as any).exp = expiresIn;
      }

      if (opts.notBefore !== undefined) {
        const notBefore = timespan(opts.notBefore, (payload as any).iat);
        
        if (typeof notBefore === 'undefined' || isNaN(notBefore)) {
          throw new Error('"notBefore" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60');
        }
        (payload as any).nbf = notBefore;
      }

      Object.keys(options_to_payload).forEach((key) => {
        const claim = options_to_payload[key];
        if (opts[key as keyof SignOptions] !== undefined) {
          (payload as any)[claim] = opts[key as keyof SignOptions];
        }
      });
    }

    // Create the secured input (header.payload)
    const encoding = opts.encoding as BufferEncoding || 'utf8';
    const securedInput = createSecuredInput(header, payload, encoding);
    
    // Get the algorithm implementation and sign
    const algorithm = getAlgorithm(header.alg);
    const signature = header.alg === 'none' 
      ? algorithm.sign(securedInput, '') 
      : algorithm.sign(securedInput, secretOrKey);
    
    // Return the complete JWT
    return `${securedInput}.${signature}`;
  }
}