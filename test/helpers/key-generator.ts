import { generateKeyPairSync, randomBytes, KeyObject } from 'crypto';

/**
 * Generate a random HMAC secret
 */
export const generateHMACSecret = (bytes = 32): Buffer => {
  return randomBytes(bytes);
};

/**
 * Generate an RSA key pair
 */
export const generateRSAKeyPair = (modulusLength = 2048): {
  publicKey: string;
  privateKey: string;
  publicKeyObject: KeyObject;
  privateKeyObject: KeyObject;
} => {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', {
    modulusLength,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  });

  const { publicKey: publicKeyObject, privateKey: privateKeyObject } = generateKeyPairSync('rsa', {
    modulusLength
  });

  return { publicKey, privateKey, publicKeyObject, privateKeyObject };
};

/**
 * Generate an EC key pair
 */
export const generateECKeyPair = (namedCurve: string = 'P-256'): {
  publicKey: string;
  privateKey: string;
  publicKeyObject: KeyObject;
  privateKeyObject: KeyObject;
} => {
  const { publicKey, privateKey } = generateKeyPairSync('ec', {
    namedCurve,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  });

  const { publicKey: publicKeyObject, privateKey: privateKeyObject } = generateKeyPairSync('ec', {
    namedCurve
  });

  return { publicKey, privateKey, publicKeyObject, privateKeyObject };
};

/**
 * Generate an Ed25519 key pair
 */
export const generateEd25519KeyPair = (): {
  publicKey: string;
  privateKey: string;
  publicKeyObject: KeyObject;
  privateKeyObject: KeyObject;
} => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  });

  const { publicKey: publicKeyObject, privateKey: privateKeyObject } = generateKeyPairSync('ed25519');

  return { publicKey, privateKey, publicKeyObject, privateKeyObject };
};

/**
 * Generate small RSA key pair (1024 bits) for testing key size validation
 */
export const generateSmallRSAKeyPair = (): {
  publicKey: KeyObject;
  privateKey: KeyObject;
} => {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 1024
  });

  return { publicKey, privateKey };
};

/**
 * Map of curve names to their standard names
 */
export const EC_CURVES = {
  'P-256': 'prime256v1',
  'P-384': 'secp384r1',
  'P-521': 'secp521r1',
  'secp256k1': 'secp256k1'
} as const;

/**
 * Generate keys for specific algorithms
 */
export const generateKeysForAlgorithm = (algorithm: string): {
  privateKey: string | Buffer | KeyObject;
  publicKey?: string | Buffer | KeyObject;
} => {
  switch (algorithm) {
    case 'HS256':
    case 'HS384':
    case 'HS512':
      return { privateKey: generateHMACSecret() };
    
    case 'RS256':
    case 'RS384':
    case 'RS512':
    case 'PS256':
    case 'PS384':
    case 'PS512':
      const rsaKeys = generateRSAKeyPair();
      return { privateKey: rsaKeys.privateKey, publicKey: rsaKeys.publicKey };
    
    case 'ES256':
      const es256Keys = generateECKeyPair('P-256');
      return { privateKey: es256Keys.privateKey, publicKey: es256Keys.publicKey };
    
    case 'ES384':
      const es384Keys = generateECKeyPair('P-384');
      return { privateKey: es384Keys.privateKey, publicKey: es384Keys.publicKey };
    
    case 'ES512':
      const es512Keys = generateECKeyPair('P-521');
      return { privateKey: es512Keys.privateKey, publicKey: es512Keys.publicKey };
    
    case 'ES256K':
      const es256kKeys = generateECKeyPair('secp256k1');
      return { privateKey: es256kKeys.privateKey, publicKey: es256kKeys.publicKey };
    
    case 'EdDSA':
      const eddsaKeys = generateEd25519KeyPair();
      return { privateKey: eddsaKeys.privateKey, publicKey: eddsaKeys.publicKey };
    
    default:
      throw new Error(`Unsupported algorithm: ${algorithm}`);
  }
};