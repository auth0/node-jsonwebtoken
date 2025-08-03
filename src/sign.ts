import { prepareSignContext, createSignature } from './lib/shared/sign-core.js';
import { SignOptions, Secret } from './types.js';

// Callback type
type SignCallback = (err: Error | null, token?: string) => void;

// Overloaded function signatures
export function sign(payload: string | Buffer | object, secretOrPrivateKey: Secret, callback: SignCallback): void;
export function sign(payload: string | Buffer | object, secretOrPrivateKey: Secret, options: SignOptions, callback: SignCallback): void;
export function sign(payload: string | Buffer | object, secretOrPrivateKey: Secret, options?: SignOptions): Promise<string>;

export function sign(
  payload: string | Buffer | object,
  secretOrPrivateKey: Secret,
  optionsOrCallback?: SignOptions | SignCallback,
  callback?: SignCallback
): Promise<string> | void {
  // Handle overloaded arguments
  let options: SignOptions = {};
  let done: SignCallback | undefined;
  
  if (typeof optionsOrCallback === 'function') {
    done = optionsOrCallback;
  } else if (optionsOrCallback) {
    options = optionsOrCallback;
    done = callback;
  }
  
  // If no callback provided, return a Promise
  if (!done) {
    return signAsync(payload, secretOrPrivateKey, options);
  }
  
  // Callback mode - handle errors
  signAsync(payload, secretOrPrivateKey, options)
    .then(token => done!(null, token))
    .catch(err => done!(err));
}

async function signAsync(
  payload: string | Buffer | object,
  secretOrPrivateKey: Secret,
  options: SignOptions
): Promise<string> {
  const context = prepareSignContext(payload, secretOrPrivateKey, options);
  const timestamp = context.isObjectPayload ? Math.floor(Date.now() / 1000) : undefined;
  
  return createSignature(context, timestamp);
}