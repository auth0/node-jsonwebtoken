import { KeyObject } from 'crypto';
import { Algorithm } from '../../types.js';

export type SecretOrKey = string | Buffer | KeyObject;

export interface AlgorithmImplementation {
  sign(message: string | Buffer, key: SecretOrKey): string;
  verify(message: string | Buffer, signature: string, key: SecretOrKey): boolean;
}

export interface AlgorithmRegistry {
  [algorithm: string]: AlgorithmImplementation;
}