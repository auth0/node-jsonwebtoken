declare module 'jws' {
  export type Algorithm = 
    | 'HS256' | 'HS384' | 'HS512'
    | 'RS256' | 'RS384' | 'RS512' 
    | 'PS256' | 'PS384' | 'PS512'
    | 'ES256' | 'ES384' | 'ES512' | 'ES256K'
    | 'EdDSA';

  export interface Header {
    alg: Algorithm;
    typ?: string;
    kid?: string;
    [key: string]: any;
  }

  export interface SignOptions {
    header: Header;
    payload: string | Buffer | object;
    secret: string | Buffer | import('crypto').KeyObject;
    encoding?: string;
    allowInsecureKeySizes?: boolean;
  }

  export interface DecodeOptions {
    json?: boolean;
  }

  export interface Decoded {
    header: Header;
    payload: string | object;
    signature: string;
  }

  export function sign(options: SignOptions): string;
  export function verify(signature: string, algorithm: Algorithm, secretOrKey: string | Buffer | import('crypto').KeyObject): boolean;
  export function decode(jwt: string, options?: DecodeOptions): Decoded | null;
}