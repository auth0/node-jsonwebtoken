import { AlgorithmRegistry } from './types.js';
import { HS256, HS384, HS512 } from './hmac.js';
import { RS256, RS384, RS512 } from './rsa.js';
import { PS256, PS384, PS512 } from './rsa-pss.js';
import { ES256, ES384, ES512, ES256K } from './ecdsa.js';
import { EdDSA } from './eddsa.js';
import { none } from './none.js';

export const algorithms: AlgorithmRegistry = {
  HS256,
  HS384,
  HS512,
  RS256,
  RS384,
  RS512,
  PS256,
  PS384,
  PS512,
  ES256,
  ES384,
  ES512,
  ES256K,
  EdDSA,
  none
};

export function getAlgorithm(name: string) {
  const algorithm = algorithms[name];
  if (!algorithm) {
    throw new Error(`Algorithm ${name} is not supported`);
  }
  return algorithm;
}

export * from './types.js';