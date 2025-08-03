import { prepareSignContext, createSignature } from './lib/shared/sign-core.js';
import { SignOptions, Secret } from './types.js';

export function signSync(
  payload: string | Buffer | object,
  secretOrPrivateKey: Secret,
  options: SignOptions = {}
): string {
  const context = prepareSignContext(payload, secretOrPrivateKey, options);
  const timestamp = context.isObjectPayload ? Math.floor(Date.now() / 1000) : undefined;
  
  return createSignature(context, timestamp);
}