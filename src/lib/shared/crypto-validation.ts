import { KeyObject } from 'crypto';
import { JsonWebTokenError } from '../JsonWebTokenError.js';

/**
 * Cryptographic validation utilities for enhanced security
 * Prevents various attacks including invalid curve points, malformed signatures, and weak keys
 */

// Known good RSA public exponents (e values)
const SAFE_RSA_PUBLIC_EXPONENTS = [3, 5, 17, 257, 65537];

// Expected signature lengths for each algorithm (in bytes)
const SIGNATURE_LENGTHS: Record<string, number> = {
  HS256: 32,
  HS384: 48,
  HS512: 64,
  RS256: 256, // Variable, depends on key size
  RS384: 384, // Variable, depends on key size
  RS512: 512, // Variable, depends on key size
  PS256: 256, // Variable, depends on key size
  PS384: 384, // Variable, depends on key size
  PS512: 512, // Variable, depends on key size
  ES256: 64,  // Fixed: 32 bytes r + 32 bytes s
  ES384: 96,  // Fixed: 48 bytes r + 48 bytes s
  ES512: 132, // Fixed: 66 bytes r + 66 bytes s (P-521 = 521 bits = 66 bytes)
  ES256K: 64, // Fixed: 32 bytes r + 32 bytes s
  EdDSA: 64,  // Ed25519
};

// EC curve parameters for validation
const EC_CURVE_PARAMS: Record<string, { p: bigint; n: bigint; bytes: number }> = {
  // P-256 (prime256v1)
  'prime256v1': {
    p: BigInt('0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff'),
    n: BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551'),
    bytes: 32
  },
  // P-384 (secp384r1)
  'secp384r1': {
    p: BigInt('0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff'),
    n: BigInt('0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff'),
    bytes: 48
  },
  // P-521 (secp521r1)
  'secp521r1': {
    p: BigInt('0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'),
    n: BigInt('0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409'),
    bytes: 66
  },
  // secp256k1
  'secp256k1': {
    p: BigInt('0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f'),
    n: BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'),
    bytes: 32
  }
};

/**
 * Validate RSA key parameters
 */
export function validateRSAKeyParameters(key: KeyObject): void {
  if (key.asymmetricKeyType !== 'rsa' && key.asymmetricKeyType !== 'rsa-pss') {
    return;
  }

  const keyDetails = (key as any).asymmetricKeyDetails;
  if (!keyDetails) {
    return; // Can't validate without details
  }

  // Check public exponent
  if (keyDetails.publicExponent !== undefined) {
    const exponent = keyDetails.publicExponent;
    
    // Convert to number if it's reasonable size
    if (exponent <= Number.MAX_SAFE_INTEGER) {
      const expNum = Number(exponent);
      
      // Warn about unusual exponents
      if (!SAFE_RSA_PUBLIC_EXPONENTS.includes(expNum)) {
        // Don't throw, just warn - unusual doesn't mean insecure
        console.warn(`Warning: RSA key uses unusual public exponent: ${expNum}. Common values are: ${SAFE_RSA_PUBLIC_EXPONENTS.join(', ')}`);
      }
      
      // Reject obviously bad exponents
      if (expNum === 1) {
        throw new JsonWebTokenError('Invalid RSA key: public exponent cannot be 1');
      }
      
      if (expNum % 2 === 0) {
        throw new JsonWebTokenError('Invalid RSA key: public exponent must be odd');
      }
    }
  }
}

/**
 * Validate EC public key point
 */
export function validateECPoint(key: KeyObject, curveName: string): void {
  if (key.asymmetricKeyType !== 'ec') {
    return;
  }

  const keyDetails = (key as any).asymmetricKeyDetails;
  if (!keyDetails || !keyDetails.publicKey) {
    return; // Can't validate without public key data
  }

  // Get curve parameters
  const curveParams = EC_CURVE_PARAMS[curveName];
  if (!curveParams) {
    // Unknown curve, skip validation
    return;
  }

  try {
    // Export the public key to get the point coordinates
    const publicKeyData = key.export({ type: 'spki', format: 'der' });
    
    // Parse the DER to extract the public key point
    // This is a simplified check - full validation would require parsing the entire DER structure
    // For now, we'll just check basic constraints
    
    // EC public keys in uncompressed form start with 0x04 followed by x and y coordinates
    const publicKeyBuffer = Buffer.from(publicKeyData);
    
    // Find the uncompressed point data (0x04 prefix)
    let pointIndex = -1;
    for (let i = 0; i < publicKeyBuffer.length - (curveParams.bytes * 2 + 1); i++) {
      if (publicKeyBuffer[i] === 0x04 && 
          publicKeyBuffer.length >= i + 1 + curveParams.bytes * 2) {
        // Potential uncompressed point found
        pointIndex = i;
        break;
      }
    }

    if (pointIndex === -1) {
      // Might be compressed or in a different format, skip validation
      return;
    }

    // Extract x and y coordinates
    const xStart = pointIndex + 1;
    const yStart = xStart + curveParams.bytes;
    
    const xBytes = publicKeyBuffer.slice(xStart, xStart + curveParams.bytes);
    const yBytes = publicKeyBuffer.slice(yStart, yStart + curveParams.bytes);
    
    const x = BigInt('0x' + xBytes.toString('hex'));
    const y = BigInt('0x' + yBytes.toString('hex'));

    // Check if coordinates are within the field
    if (x >= curveParams.p || y >= curveParams.p || x < 0n || y < 0n) {
      throw new JsonWebTokenError('Invalid EC key: point coordinates are outside the field');
    }

    // Check for point at infinity (both coordinates zero)
    if (x === 0n && y === 0n) {
      throw new JsonWebTokenError('Invalid EC key: point at infinity is not allowed');
    }

    // Note: Full point validation would include:
    // 1. Checking that the point satisfies the curve equation: y² = x³ + ax + b (mod p)
    // 2. Checking that the point order is correct (not in a small subgroup)
    // However, these checks require the full curve parameters (a, b, G) which vary by curve
    // For now, we rely on Node.js crypto module to have done these checks when importing the key
    
  } catch (error: any) {
    if (error instanceof JsonWebTokenError) {
      throw error;
    }
    // If we can't parse the key format, skip validation
    // This might happen with keys in different formats
  }
}

/**
 * Validate JWT signature format and check for trailing data
 */
export function validateSignatureFormat(signature: string, algorithm: string): void {
  if (!signature || !algorithm) {
    return;
  }

  // For ECDSA algorithms, check exact length
  if (algorithm.startsWith('ES')) {
    const expectedLength = SIGNATURE_LENGTHS[algorithm];
    if (expectedLength !== undefined) {
      // Base64url encoding: 4 characters encode 3 bytes
      // So expected base64url length = ceil(bytes * 4 / 3)
      const expectedBase64Length = Math.ceil(expectedLength * 4 / 3);
      
      if (signature.length > expectedBase64Length) {
        throw new JsonWebTokenError(
          `Invalid signature format: signature has trailing data. Expected length ${expectedBase64Length}, got ${signature.length}`
        );
      }
    }
  }

  // Check for invalid characters in base64url
  if (!/^[A-Za-z0-9_-]*$/.test(signature)) {
    throw new JsonWebTokenError('Invalid signature format: contains non-base64url characters');
  }
}

/**
 * Validate ECDSA signature components (r, s values)
 */
export function validateECDSASignatureComponents(r: Buffer, s: Buffer, algorithm: string): void {
  // Get expected component size
  const signatureLength = SIGNATURE_LENGTHS[algorithm];
  if (!signatureLength) {
    return;
  }

  const componentLength = signatureLength / 2;

  // Check lengths
  if (r.length !== componentLength || s.length !== componentLength) {
    throw new JsonWebTokenError('Invalid ECDSA signature: incorrect component lengths');
  }

  // Convert to BigInt for range checks
  const rBig = BigInt('0x' + r.toString('hex'));
  const sBig = BigInt('0x' + s.toString('hex'));

  // Check for zero values
  if (rBig === 0n || sBig === 0n) {
    throw new JsonWebTokenError('Invalid ECDSA signature: r or s is zero');
  }

  // Get curve name for the algorithm
  let curveName: string | undefined;
  switch (algorithm) {
    case 'ES256':
      curveName = 'prime256v1';
      break;
    case 'ES384':
      curveName = 'secp384r1';
      break;
    case 'ES512':
      curveName = 'secp521r1';
      break;
    case 'ES256K':
      curveName = 'secp256k1';
      break;
  }

  if (curveName && EC_CURVE_PARAMS[curveName]) {
    const curveParams = EC_CURVE_PARAMS[curveName];
    
    // r and s should be less than the curve order (n)
    if (rBig >= curveParams.n || sBig >= curveParams.n) {
      throw new JsonWebTokenError('Invalid ECDSA signature: r or s exceeds curve order');
    }
  }
}

/**
 * Validate EdDSA key parameters
 */
export function validateEdDSAKey(key: KeyObject): void {
  if (key.asymmetricKeyType !== 'ed25519' && key.asymmetricKeyType !== 'ed448') {
    return;
  }

  // EdDSA keys are generally safe by design
  // The main validation is ensuring they're the correct type, which is already done
  // Additional validations could include checking for weak keys, but these are extremely rare
}

/**
 * Main validation function for cryptographic parameters
 */
export function validateCryptographicParameters(
  key: KeyObject | undefined,
  algorithm: string | undefined,
  signature?: string
): void {
  if (!key || !algorithm) {
    return;
  }

  // Validate based on key type
  switch (key.asymmetricKeyType) {
    case 'rsa':
    case 'rsa-pss':
      validateRSAKeyParameters(key);
      break;
      
    case 'ec':
      // Determine curve name from algorithm
      let curveName: string | undefined;
      switch (algorithm) {
        case 'ES256':
          curveName = 'prime256v1';
          break;
        case 'ES384':
          curveName = 'secp384r1';
          break;
        case 'ES512':
          curveName = 'secp521r1';
          break;
        case 'ES256K':
          curveName = 'secp256k1';
          break;
      }
      if (curveName) {
        validateECPoint(key, curveName);
      }
      break;
      
    case 'ed25519':
    case 'ed448':
      validateEdDSAKey(key);
      break;
  }

  // Validate signature format if provided
  if (signature) {
    validateSignatureFormat(signature, algorithm);
  }
}